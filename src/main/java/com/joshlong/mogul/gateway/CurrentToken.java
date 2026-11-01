package com.joshlong.mogul.gateway;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * use to obtain the current access token for the current authenticated
 * {@link java.security.Principal}. the token lives in the http session, with the login it
 * came from, so it only exists inside a request.
 */
@Component
class CurrentToken {

	private final OAuth2AuthorizedClientRepository authorizedClientRepository;

	CurrentToken(OAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Nullable
	String getAccessToken(OAuth2AuthenticationToken authentication) {
		if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes))
			return null;
		var client = this.authorizedClientRepository.loadAuthorizedClient(
				authentication.getAuthorizedClientRegistrationId(), authentication, attributes.getRequest());
		return client == null ? null : client.getAccessToken().getTokenValue();
	}

}
