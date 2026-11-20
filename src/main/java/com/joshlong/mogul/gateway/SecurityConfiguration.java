package com.joshlong.mogul.gateway;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * a useful fix from <a href="https://github.com/okta/okta-spring-boot/issues/596">Matt
 * Raible</a>
 */
@Configuration
class SecurityConfiguration {

	private final Logger log = LoggerFactory.getLogger(getClass());

	/**
	 * the apps (mogul clip on android and ios) are oauth clients of their own: they log
	 * in to auth0 with pkce and call the api with a bearer token. for those requests the
	 * gateway is a resource server, not a client: it checks the token as the api does
	 * and, since the token relay only acts for someone who logged in here, passes the
	 * token along untouched. no session, and a bad token is a 401, not a trip to the
	 * login page. only the api is reachable this way.
	 */
	@Bean
	@Order(1)
	SecurityFilterChain bearerTokenSecurityFilterChain(HttpSecurity http) throws Exception {
		return http//
			.securityMatcher(this::isBearerTokenApiRequest)//
			.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())//
			.oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))//
			.sessionManagement(sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//
			.csrf(AbstractHttpConfigurer::disable)//
			.build();
	}

	private boolean isBearerTokenApiRequest(HttpServletRequest request) {
		var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		return request.getRequestURI().startsWith("/api/") && authorization != null
				&& authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length());
	}

	@Bean
	@Order(2)
	SecurityFilterChain securityFilterChain(@Value("${auth0.audience}") String audience,
			ClientRegistrationRepository clientRegistrationRepository, HttpSecurity http) throws Exception {
		// one resolver for every trip to auth0. logging in uses it, and so does quietly
		// fetching a new token for someone still logged in but without one -- which
		// happens after a token expires, or the gateway restarts. auth0 only issues a
		// token the api can verify when it's asked for the audience; without it, it
		// issues an encrypted one meant for nobody, and every api call is a 401.
		var authorizationRequestResolver = this.authorizationRequestResolver(audience, clientRegistrationRepository);
		return http//
			.authorizeHttpRequests((authorize) -> authorize//
				.requestMatchers(EndpointRequest.toAnyEndpoint())
				.permitAll()//
				.requestMatchers("/login", "/wp")
				.permitAll() //
				.anyRequest()
				.authenticated()//
			)//
			.oauth2Login(oauth2 -> oauth2//
				.authorizationEndpoint(ae -> ae.authorizationRequestResolver(authorizationRequestResolver))
				.failureHandler(this::authenticationFailed)//
			)
			.exceptionHandling(a -> a.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
			.csrf(AbstractHttpConfigurer::disable)//
			.oauth2Client(client -> client
				.authorizationCodeGrant(grant -> grant.authorizationRequestResolver(authorizationRequestResolver)))//
			.build();
	}

	/**
	 * the default failure handler redirects to {@code /login?error}, and {@code /login}
	 * unconditionally redirects back to the authorization endpoint -- so a login that
	 * fails bounces between here and auth0 forever, rendering nothing and (at the default
	 * log levels) saying nothing. fail loudly instead.
	 */
	private void authenticationFailed(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response,
			org.springframework.security.core.AuthenticationException exception) throws java.io.IOException {
		this.log.error("oauth2 login failed", exception);
		// write the response directly: sendError() dispatches to /error, which is itself
		// authenticated, which sends us right back to /login and into the same loop.
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("text/plain;charset=utf-8");
		response.getWriter().write("oauth2 login failed: " + exception.getMessage());
	}

	private OAuth2AuthorizationRequestResolver authorizationRequestResolver(String audience,
			ClientRegistrationRepository clientRegistrationRepository) {
		var authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
		authorizationRequestResolver.setAuthorizationRequestCustomizer(
				customizer -> customizer.additionalParameters(params -> params.put("audience", audience)));
		return authorizationRequestResolver;
	}

}
