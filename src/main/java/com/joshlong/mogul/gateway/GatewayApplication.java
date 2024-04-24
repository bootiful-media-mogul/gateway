package com.joshlong.mogul.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.mvc.ProxyExchange;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.rewritePath;
import static org.springframework.cloud.gateway.server.mvc.filter.TokenRelayFilterFunctions.tokenRelay;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;

@SpringBootApplication
@Controller
@ResponseBody
@EnableConfigurationProperties(GatewayProperties.class)
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	/*
	 * @Bean RouteLocator gateway(RouteLocatorBuilder rlb, @Value("${mogul.gateway.ui}")
	 * String ui,
	 *
	 * @Value("${mogul.gateway.api}") String api) { var apiPrefix = "/api/"; return rlb//
	 * .routes() .route(rs -> rs.path(apiPrefix + "**") .filters(f ->
	 * f.tokenRelay().rewritePath(apiPrefix + "(?<segment>.*)", "/$\\{segment}"))
	 * .uri(api)) .route(rs -> rs.path("/**").uri(ui)) .build(); }
	 */

	static final String UI_PREFIX = "/";
	static final String UI_HOST = "http://localhost:5173";

	static final String API_PREFIX = "/api/";
	static final String API_HOST = "http://localhost:8080";

	static final String WILDCARD = "**";

	@Bean
	RouterFunction<ServerResponse> apiRouteGets() {
		return route("apiRouteGets").GET(API_PREFIX + WILDCARD, http(API_HOST))
			.before(rewritePath(API_PREFIX + "(?<segment>.*)", "/${segment}"))
			.filter(tokenRelay())
			.build();
	}

	@Bean
	RouterFunction<ServerResponse> apiRoutePosts() {
		return route("apiRoutePosts").POST(API_PREFIX + WILDCARD, http(API_HOST))
			.before(rewritePath(API_PREFIX + "(?<segment>.*)", "/${segment}"))
			.filter(tokenRelay())
			.build();
	}

	@Bean
	RouterFunction<ServerResponse> apiRouteOptions() {
		return route("apiRouteOptions").OPTIONS(API_PREFIX + WILDCARD, http(API_HOST))
			.before(rewritePath(API_PREFIX + "(?<segment>.*)", "/${segment}"))
			.filter(tokenRelay())
			.build();
	}

	@GetMapping(UI_PREFIX + WILDCARD)
	ResponseEntity<?> ui(ProxyExchange<?> request) {
		var path = request.path(UI_PREFIX);
		return request.uri(URI.create(UI_HOST + "/" + path)).get();
	}

	@Bean
	SecurityFilterChain mySecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.authorizeHttpRequests(a -> a.anyRequest().authenticated())
			.csrf(AbstractHttpConfigurer::disable)
			.cors(AbstractHttpConfigurer::disable)
			.oauth2Login(Customizer.withDefaults())
			.oauth2Client(Customizer.withDefaults())
			.build();
	}

}