package com.joshlong.mogul.gateway;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
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
 * <p>
 * this is the one place the gateway registers serialization hints. add new types to the
 * group that explains why they end up in the session.
 */
class SessionTokenHints implements RuntimeHintsRegistrar {

	/**
	 * the authorized client: the access token, the refresh token and the client
	 * registration they were issued for.
	 */
	private static final Class<?>[] AUTHORIZED_CLIENT = { OAuth2AuthorizedClient.class, ClientRegistration.class,
			ClientRegistration.ProviderDetails.class, ClientRegistration.ProviderDetails.UserInfoEndpoint.class,
			ClientRegistration.ClientSettings.class, AuthorizationGrantType.class, ClientAuthenticationMethod.class,
			AuthenticationMethod.class };

	/**
	 * every kind of token that can show up in the session, directly or inside something
	 * else.
	 */
	private static final Class<?>[] TOKENS = { AbstractOAuth2Token.class, OAuth2AccessToken.class,
			OAuth2AccessToken.TokenType.class, OAuth2RefreshToken.class, OAuth2DeviceCode.class, OAuth2UserCode.class,
			OidcIdToken.class, OidcLogoutToken.class, Jwt.class };

	/**
	 * the authorization request, saved between the redirect to auth0 and the callback.
	 */
	private static final Class<?>[] AUTHORIZATION_REQUEST = { OAuth2AuthorizationRequest.class,
			OAuth2AuthorizationResponseType.class };

	/**
	 * the security context of a logged-in oidc user.
	 */
	private static final Class<?>[] SECURITY_CONTEXT = { OAuth2AuthenticationToken.class, DefaultOidcUser.class,
			DefaultOAuth2User.class, OidcUserInfo.class, AddressStandardClaim.class, OidcUserAuthority.class,
			OAuth2UserAuthority.class, FactorGrantedAuthority.class };

	/**
	 * {@code SPRING_SECURITY_LAST_EXCEPTION}, left in the session after a failed login.
	 */
	private static final Class<?>[] LOGIN_FAILURE = { OAuth2AuthenticationException.class,
			OAuth2AuthorizationException.class, OAuth2Error.class };

	/**
	 * the jdk types the claims, attributes and saved request are made of.
	 */
	private static final Class<?>[] JDK = { Instant.class, URL.class, URI.class, Boolean.class, Double.class,
			String[].class, HashMap.class, LinkedHashMap.class, HashSet.class, LinkedHashSet.class };

	/**
	 * jdk types that aren't public, so they can only be named. {@code java.time.Ser} is
	 * the serialized form of every {@code java.time} type, {@link Instant} included.
	 */
	private static final String[] JDK_INTERNAL = { "java.time.Ser", "java.util.Collections$UnmodifiableMap",
			"java.util.Collections$UnmodifiableSet", "java.util.Collections$UnmodifiableCollection",
			"java.util.Collections$UnmodifiableList", "java.util.Collections$UnmodifiableRandomAccessList",
			"java.util.Collections$SingletonList", "java.util.Collections$EmptySet", "java.util.Collections$EmptyList",
			"java.util.Collections$EmptyMap", "java.util.Arrays$ArrayList" };

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		for (var group : new Class<?>[][] { AUTHORIZED_CLIENT, TOKENS, AUTHORIZATION_REQUEST, SECURITY_CONTEXT,
				LOGIN_FAILURE, JDK })
			for (var type : group)
				register(hints, TypeReference.of(type));
		for (var type : JDK_INTERNAL)
			register(hints, TypeReference.of(type));
	}

	private static void register(RuntimeHints hints, TypeReference type) {
		hints.reflection().registerType(type, builder -> builder.withJavaSerialization(true));
	}

}
