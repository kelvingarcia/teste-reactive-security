package org.fatec.scs.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;

@Configuration
public class SecurityConfiguration {

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
			ReactiveAuthenticationManager jwtAuthenticationManager,
			ServerAuthenticationConverter jwtAuthenticationConverter) {
		AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(jwtAuthenticationManager);
		authenticationWebFilter.setServerAuthenticationConverter(jwtAuthenticationConverter);
		
		return http.authorizeExchange()
				.pathMatchers("/user/signup").permitAll()
				.pathMatchers("/user/login").permitAll()
				.pathMatchers("/user").authenticated()
				.and()
				.addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
				.httpBasic().disable()
				.csrf().disable()
				.formLogin().disable()
				.logout().disable()
				.build();
	}
	
}
