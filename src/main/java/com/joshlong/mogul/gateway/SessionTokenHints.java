package com.joshlong.mogul.gateway;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

/**
 * spring session writes the http session to redis with java serialization, and a native
 * image can only (de)serialize what it was told about. spring security's own hints cover
 * the basics of the security context, but not what an oauth2 login puts in the session:
 * the in-flight authorization request, the oidc user and its authorities, and the access
 * token -- an {@code OAuth2AuthorizedClient} and everything it holds. without these, any
 * request carrying a session cookie dies with a 500 trying to read the session back.
 */
class SessionTokenHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		for (var type : new Class<?>[] {
				// the authorized client (access token) repository
				OAuth2AuthorizedClient.class, ClientRegistration.class, ClientRegistration.ProviderDetails.class,
				ClientRegistration.ProviderDetails.UserInfoEndpoint.class, ClientRegistration.ClientSettings.class,
				AbstractOAuth2Token.class, OAuth2AccessToken.class, OAuth2AccessToken.TokenType.class,
				OAuth2RefreshToken.class, AuthorizationGrantType.class, ClientAuthenticationMethod.class,
				AuthenticationMethod.class,
				// the authorization request, saved between the redirect to auth0 and the
				// callback
				OAuth2AuthorizationRequest.class, OAuth2AuthorizationResponseType.class,
				// the security context of a logged-in oidc user
				OAuth2AuthenticationToken.class, DefaultOidcUser.class, DefaultOAuth2User.class, OidcIdToken.class,
				OidcUserInfo.class, OidcUserAuthority.class, OAuth2UserAuthority.class, FactorGrantedAuthority.class,
				// SPRING_SECURITY_LAST_EXCEPTION, after a failed login
				OAuth2AuthenticationException.class, OAuth2AuthorizationException.class, OAuth2Error.class,
				// what the claims, attributes and saved request are made of
				Instant.class, URL.class, Boolean.class, Double.class, String[].class, HashMap.class,
				LinkedHashMap.class, HashSet.class, LinkedHashSet.class })
			hints.reflection().registerType(type, builder -> builder.withJavaSerialization(true));

		for (var type : new String[] { "java.time.Ser", "java.util.Collections$UnmodifiableMap",
				"java.util.Collections$UnmodifiableSet", "java.util.Collections$UnmodifiableCollection",
				"java.util.Collections$UnmodifiableList", "java.util.Collections$UnmodifiableRandomAccessList",
				"java.util.Collections$SingletonList", "java.util.Collections$EmptySet",
				"java.util.Collections$EmptyList", "java.util.Collections$EmptyMap", "java.util.Arrays$ArrayList" })
			hints.reflection().registerType(TypeReference.of(type), builder -> builder.withJavaSerialization(true));
	}

}
