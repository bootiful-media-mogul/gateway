package com.joshlong.mogul.gateway;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.http.client.autoconfigure.HttpClientAutoConfiguration;
import org.springframework.boot.http.client.autoconfigure.imperative.ImperativeHttpClientAutoConfiguration;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.autoconfigure.DispatcherServletAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.cloud.gateway.server.mvc.GatewayServerMvcAutoConfiguration;
import org.springframework.cloud.gateway.server.mvc.config.GatewayMvcProperties;
import org.springframework.cloud.gateway.server.mvc.filter.FilterAutoConfiguration;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctionAutoConfiguration;
import org.springframework.cloud.gateway.server.mvc.handler.ProxyExchange;
import org.springframework.cloud.gateway.server.mvc.predicate.PredicateAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * an app's bearer token has to reach the api: through the gateway's real api route (the
 * proxy, the retry, the token relay), to a stand-in api listening on a real port.
 */
@SpringBootTest(classes = BearerTokenProxyTest.Config.class)
class BearerTokenProxyTest {

	private static final String GOOD_TOKEN = "good";

	private static final AtomicReference<String> RECEIVED_AUTHORIZATION = new AtomicReference<>();

	private static HttpServer api;

	@Autowired
	private WebApplicationContext context;

	@BeforeAll
	static void startTheApi() throws IOException {
		api = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		api.createContext("/", exchange -> {
			RECEIVED_AUTHORIZATION.set(exchange.getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION));
			var body = "{\"data\":{}}".getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
			exchange.sendResponseHeaders(200, body.length);
			exchange.getResponseBody().write(body);
			exchange.close();
		});
		api.start();
	}

	@AfterAll
	static void stopTheApi() {
		api.stop(0);
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("auth0.audience", () -> "https://api.mogul.tools");
		registry.add("mogul.gateway.api", () -> "http://127.0.0.1:" + api.getAddress().getPort());
	}

	@Test
	void theAppsTokenReachesTheApi() throws Exception {
		var mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
		var response = mvc
			.perform(post("/api/graphql").header(HttpHeaders.AUTHORIZATION, "Bearer " + GOOD_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"query\":\"{ me { id } }\"}"))
			.andReturn()
			.getResponse();
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(RECEIVED_AUTHORIZATION.get()).isEqualTo("Bearer " + GOOD_TOKEN);
	}

	@Configuration
	@EnableWebSecurity
	@ImportAutoConfiguration({ JacksonAutoConfiguration.class, HttpMessageConvertersAutoConfiguration.class,
			HttpClientAutoConfiguration.class, ImperativeHttpClientAutoConfiguration.class,
			RestClientAutoConfiguration.class, DispatcherServletAutoConfiguration.class, WebMvcAutoConfiguration.class,
			GatewayServerMvcAutoConfiguration.class, FilterAutoConfiguration.class,
			HandlerFunctionAutoConfiguration.class, PredicateAutoConfiguration.class })
	@Import(SecurityConfiguration.class)
	static class Config {

		// the gateway's own beans, as GatewayApplication defines them
		private final GatewayApplication gateway = new GatewayApplication();

		@Bean
		JdkClientHttpRequestFactory gatewayClientHttpRequestFactory() {
			return this.gateway.gatewayClientHttpRequestFactory();
		}

		@Bean
		ProxyExchange proxyExchange(RestClient.Builder restClientBuilder, GatewayMvcProperties gatewayMvcProperties) {
			return this.gateway.proxyExchange(restClientBuilder, gatewayMvcProperties);
		}

		@Bean
		RouterFunction<ServerResponse> apiRoute(
				@org.springframework.beans.factory.annotation.Value("${mogul.gateway.api}") String api) {
			return this.gateway.apiRoute(
					new WordpressAwareTokenRelayFilterFunction(new HttpSessionOAuth2AuthorizedClientRepository()), api);
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("auth0")
				.clientId("gateway")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
				.authorizationUri("https://mogul.test/authorize")
				.tokenUri("https://mogul.test/oauth/token")
				.build());
		}

		@Bean
		JwtDecoder jwtDecoder() {
			return token -> {
				if (!GOOD_TOKEN.equals(token))
					throw new BadJwtException("not a token auth0 issued");
				return Jwt.withTokenValue(token)
					.header("alg", "RS256")
					.subject("auth0|josh")
					.issuedAt(Instant.now())
					.expiresAt(Instant.now().plusSeconds(60))
					.build();
			};
		}

	}

}
