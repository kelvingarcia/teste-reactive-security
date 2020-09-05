package org.fatec.scs.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {
	
	@Autowired
	private JwtSigner jwtSigner;

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.just(authentication)
				.map(auth -> jwtSigner.validateJws((String) auth.getCredentials()))
				.onErrorResume(throwable -> Mono.empty())
				.map(jws -> new UsernamePasswordAuthenticationToken(
						jws.getBody().getSubject(), 
						(String) authentication.getCredentials(),
						List.of(new SimpleGrantedAuthority("ROLE_USER"))));
	}

}
