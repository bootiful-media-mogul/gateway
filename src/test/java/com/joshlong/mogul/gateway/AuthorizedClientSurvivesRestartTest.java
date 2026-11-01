package com.joshlong.mogul.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * the access token the gateway relays to the api has to outlive the gateway. the session
 * already does -- it's in redis -- so a token kept anywhere but the session leaves a
 * logged-in user with no token after a restart, and every api call bounces to /login.
 * <p>
 * a "restart" here is a fresh repository and a session that has been through java
 * serialization, which is what a round trip through redis does to it.
 */
class AuthorizedClientSurvivesRestartTest {

	private final ClientRegistration auth0 = ClientRegistration.withRegistrationId("auth0")
		.clientId("a-client")
		.clientSecret("a-secret")
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
		.authorizationUri("https://example.auth0.com/authorize")
		.tokenUri("https://example.auth0.com/oauth/token")
		.userInfoUri("https://example.auth0.com/userinfo")
		.userNameAttributeName("sub")
		.build();

	private final TestingAuthenticationToken josh = new TestingAuthenticationToken("josh", null, "ROLE_USER");

	private OAuth2AuthorizedClient authorizedClient() {
		var issued = Instant.now();
		return new OAuth2AuthorizedClient(this.auth0, "josh", new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"an-access-token", issued, issued.plusSeconds(3600)),
				new OAuth2RefreshToken("a-refresh-token", issued));
	}

	/** what a redis round trip does to the session's attributes */
	private static MockHttpSession throughRedis(MockHttpSession session) throws Exception {
		var attributes = new HashMap<String, Object>();
		for (var name : Collections.list(session.getAttributeNames()))
			attributes.put(name, session.getAttribute(name));
		var bytes = new ByteArrayOutputStream();
		try (var out = new ObjectOutputStream(bytes)) {
			out.writeObject(attributes);
		}
		try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
			@SuppressWarnings("unchecked")
			var restored = (HashMap<String, Object>) in.readObject();
			var fresh = new MockHttpSession(null, session.getId());
			restored.forEach(fresh::setAttribute);
			return fresh;
		}
	}

	private OAuth2AuthorizedClient afterARestart(Supplier<OAuth2AuthorizedClientRepository> gateway) throws Exception {
		var session = new MockHttpSession();
		var login = new MockHttpServletRequest();
		login.setSession(session);
		gateway.get().saveAuthorizedClient(this.authorizedClient(), this.josh, login, new MockHttpServletResponse());
		var later = new MockHttpServletRequest();
		later.setSession(throughRedis(session));
		return gateway.get().loadAuthorizedClient("auth0", this.josh, later);
	}

	@Test
	void anInMemoryTokenIsLostWhenTheGatewayRestarts() throws Exception {
		// how the gateway kept tokens: in a map in its own heap
		var lost = this.afterARestart(() -> new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
				new InMemoryOAuth2AuthorizedClientService(new InMemoryClientRegistrationRepository(this.auth0))));
		assertThat(lost).isNull();
	}

	@Test
	void aTokenInTheSessionSurvivesTheGatewayRestarting() throws Exception {
		var survived = this.afterARestart(HttpSessionOAuth2AuthorizedClientRepository::new);
		assertThat(survived).isNotNull();
		assertThat(survived.getAccessToken().getTokenValue()).isEqualTo("an-access-token");
		assertThat(survived.getRefreshToken().getTokenValue()).isEqualTo("a-refresh-token");
		assertThat(survived.getClientRegistration().getRegistrationId()).isEqualTo("auth0");
	}

}
