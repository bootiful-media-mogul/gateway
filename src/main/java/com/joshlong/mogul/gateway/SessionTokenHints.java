package com.joshlong.mogul.gateway;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

/**
 * spring session writes the http session to redis with java serialization, and a native
 * image can only serialize what it was told about. spring session already covers the
 * security context; the access token next to it -- an {@code OAuth2AuthorizedClient} and
 * everything it holds -- is this.
 */
class SessionTokenHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		for (var type : new Class<?>[] { OAuth2AuthorizedClient.class, ClientRegistration.class,
				ClientRegistration.ProviderDetails.class, ClientRegistration.ProviderDetails.UserInfoEndpoint.class,
				ClientRegistration.ClientSettings.class, AbstractOAuth2Token.class, OAuth2AccessToken.class,
				OAuth2AccessToken.TokenType.class, OAuth2RefreshToken.class, AuthorizationGrantType.class,
				ClientAuthenticationMethod.class, AuthenticationMethod.class, Instant.class, HashMap.class,
				LinkedHashMap.class, HashSet.class, LinkedHashSet.class })
			hints.reflection().registerType(type, builder -> builder.withJavaSerialization(true));

		for (var type : new String[] { "java.time.Ser", "java.util.Collections$UnmodifiableMap",
				"java.util.Collections$UnmodifiableSet", "java.util.Collections$UnmodifiableCollection",
				"java.util.Collections$EmptySet" })
			hints.reflection().registerType(TypeReference.of(type), builder -> builder.withJavaSerialization(true));
	}

}
