package com.joshlong.mogul.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * auth0 only mints a token the api can verify when it's asked for one with an
 * {@code audience}. without it, it hands back an encrypted token meant for nobody, and
 * the api answers 401: "Encrypted JWT rejected". so every way the gateway sends someone
 * to auth0 has to ask for the audience -- logging in, and also quietly getting a new
 * token for someone who is still logged in but has none, which is what happens after the
 * token expires or the gateway forgets it.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ReauthorizationAudienceTest {

	@Autowired
	MockMvc mvc;

	private static OAuth2AuthenticationToken loggedIn() {
		var authorities = List.of(new SimpleGrantedAuthority("OIDC_USER"));
		var user = new DefaultOAuth2User(authorities, Map.of("sub", "auth0|josh"), "sub");
		return new OAuth2AuthenticationToken(user, authorities, "auth0");
	}

	private static String audienceOf(String location) {
		assertThat(location).as("a redirect to auth0").contains("/authorize?");
		var query = location.substring(location.indexOf('?') + 1);
		for (var parameter : query.split("&"))
			if (parameter.startsWith("audience="))
				return parameter.substring("audience=".length());
		return null;
	}

	@Test
	void loggingInAsksForTheAudience() throws Exception {
		var location = this.mvc.perform(get("/oauth2/authorization/auth0"))
			.andReturn()
			.getResponse()
			.getRedirectedUrl();
		assertThat(audienceOf(location)).endsWith("/api/v2/");
	}

	@Test
	void gettingANewTokenForSomeoneLoggedInAsksForTheAudienceToo() throws Exception {
		// logged in, but with no token: the token relay sends them back to auth0 for one
		var response = this.mvc
			.perform(post("/api/graphql").with(authentication(loggedIn()))
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"query\":\"{__typename}\"}"))
			.andReturn()
			.getResponse();
		var location = response.getRedirectedUrl();
		assertThat(location).as("the relay should have sent them to auth0").isNotNull();
		assertThat(audienceOf(location)).endsWith("/api/v2/");
	}

}
