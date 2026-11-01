package com.joshlong.mogul.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * the types below are what a real session in redis held after an auth0 login: the
 * authorization request, the oidc security context, the saved request and the authorized
 * client. a native gateway that can't deserialize any one of them 500s on every request
 * carrying that session's cookie.
 */
class SessionTokenHintsTests {

	@Test
	void registersJavaSerializationForEverythingAnOauth2LoginPutsInTheSession() {
		var hints = new RuntimeHints();
		new SessionTokenHints().registerHints(hints, getClass().getClassLoader());

		for (var type : new String[] { "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest",
				"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType",
				"org.springframework.security.oauth2.core.oidc.OidcIdToken",
				"org.springframework.security.oauth2.core.oidc.OidcUserInfo",
				"org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser",
				"org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority",
				"org.springframework.security.oauth2.core.user.DefaultOAuth2User",
				"org.springframework.security.oauth2.core.user.OAuth2UserAuthority",
				"org.springframework.security.oauth2.client.OAuth2AuthorizedClient",
				"org.springframework.security.oauth2.core.OAuth2AccessToken",
				"org.springframework.security.oauth2.core.OAuth2DeviceCode",
				"org.springframework.security.oauth2.core.OAuth2UserCode",
				"org.springframework.security.oauth2.core.oidc.AddressStandardClaim",
				"org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken",
				"org.springframework.security.oauth2.jwt.Jwt", "java.net.URL", "java.net.URI", "java.lang.Boolean",
				"java.time.Ser", "java.util.Collections$UnmodifiableMap" }) {
			var hint = hints.reflection().getTypeHint(TypeReference.of(type));
			assertThat(hint).as(type).isNotNull();
			assertThat(hint.hasJavaSerialization()).as(type).isTrue();
		}
	}

}
