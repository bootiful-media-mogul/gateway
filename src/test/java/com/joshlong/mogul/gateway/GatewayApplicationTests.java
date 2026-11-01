package com.joshlong.mogul.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class GatewayApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void tokensAreKeptInTheSession(@Autowired OAuth2AuthorizedClientRepository authorizedClientRepository) {
		// the session is in redis and outlives this node; anywhere else, a restart loses
		// the token of everyone logged in. see AuthorizedClientSurvivesRestartTest.
		assertThat(authorizedClientRepository).isInstanceOf(HttpSessionOAuth2AuthorizedClientRepository.class);
	}

}
