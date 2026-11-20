package com.joshlong.mogul.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

import java.time.Instant;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.cloud.gateway.server.mvc.filter.TokenRelayFilterFunctions.tokenRelay;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * the apps call the api with their own auth0 bearer token, and the gateway checks it and
 * passes it along. the browser's login is untouched. this stands up only the security
 * configuration and an api route behind the real token relay, so it needs neither auth0
 * nor redis nor rabbitmq.
 */
@SpringJUnitWebConfig(BearerTokenSecurityTest.Config.class)
@TestPropertySource(properties = "auth0.audience=https://api.mogul.tools")
class BearerTokenSecurityTest {

	private static final String GOOD_TOKEN = "good";

	private final MockMvc mvc;

	BearerTokenSecurityTest(WebApplicationContext context) {
		this.mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
	}

	@Test
	void aValidBearerTokenReachesTheApiUntouched() throws Exception {
		var response = this.mvc.perform(post("/api/graphql").header(HttpHeaders.AUTHORIZATION, "Bearer " + GOOD_TOKEN))
			.andReturn()
			.getResponse();
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(response.getContentAsString()).isEqualTo("Bearer " + GOOD_TOKEN);
		assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).as("no session for a bearer token").isNull();
	}

	@Test
	void aBadBearerTokenIsA401NotALoginPage() throws Exception {
		var response = this.mvc.perform(post("/api/graphql").header(HttpHeaders.AUTHORIZATION, "Bearer forged"))
			.andReturn()
			.getResponse();
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
		assertThat(response.getRedirectedUrl()).isNull();
	}

	@Test
	void theBrowserStillLogsInAsBefore() throws Exception {
		var response = this.mvc.perform(post("/api/graphql")).andReturn().getResponse();
		assertThat(response.getRedirectedUrl()).endsWith("/login");
	}

	@Test
	void aBearerTokenOnlyReachesTheApi() throws Exception {
		var response = this.mvc.perform(get("/").header(HttpHeaders.AUTHORIZATION, "Bearer " + GOOD_TOKEN))
			.andReturn()
			.getResponse();
		assertThat(response.getRedirectedUrl()).endsWith("/login");
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@Import(SecurityConfiguration.class)
	static class Config {

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			var auth0 = ClientRegistration.withRegistrationId("auth0")
				.clientId("gateway")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
				.authorizationUri("https://mogul.test/authorize")
				.tokenUri("https://mogul.test/oauth/token")
				.build();
			return new InMemoryClientRegistrationRepository(auth0);
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

		// stands in for the api: answers with the authorization header it was sent
		@Bean
		RouterFunction<ServerResponse> api() {
			return RouterFunctions.route()
				.POST("/api/graphql",
						request -> ServerResponse.ok()
							.body(Objects.requireNonNullElse(request.headers().firstHeader(HttpHeaders.AUTHORIZATION),
									"")))
				.filter(tokenRelay())
				.build();
		}

	}

}
