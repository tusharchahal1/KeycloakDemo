package com.keycloak.demo.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityFilter {

	@Autowired
	private JwtAuthConverter jwtAuthConverter;

	@Bean
	public SecurityFilterChain filter(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests()
		.requestMatchers(HttpMethod.GET, "/api/admin").hasRole("admin")
		.requestMatchers(HttpMethod.GET, "/api/user").hasRole("user")
		.anyRequest().authenticated();

		http
		.oauth2ResourceServer()
		.jwt()
		.jwtAuthenticationConverter(jwtAuthConverter);

		http
		.sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		return http.build();

	}

}
