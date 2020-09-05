package org.fatec.scs.security;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/user")
public class UserController {
	
	@Autowired
	private JwtSigner jwtSigner;
	
	private Map<String, UserCredentials> users = new HashMap<>();
	
	public UserController() {
		users.put("example@example.com", new UserCredentials("example@example.com", "pw"));
	}
	
	@PutMapping("/signup")
	public Mono<ResponseEntity<Void>> signUp(@RequestBody UserCredentials user) {
		users.put(user.email(), user);
		return Mono.just(ResponseEntity.noContent().<Void>build());		
	}
	
	@PostMapping("/login")
	public Mono<ResponseEntity<Void>> login(@RequestBody UserCredentials user) {
		return Mono.justOrEmpty(users.get(user.email()))
				.filter(u -> u.password().equals(user.password()))
				.map(u -> {
					var jwt = jwtSigner.createJwt(u.email());
					var authCookie = ResponseCookie.fromClientResponse("X-Auth", jwt)
							.maxAge(3600)
							.httpOnly(true)
							.path("/")
							.secure(false)
							.build();
					return ResponseEntity.noContent()
							.header("Set-Cookie", authCookie.toString())
							.<Void>build();
				})
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).<Void>build()));
	}
	
	@GetMapping
	public Mono<ResponseEntity<User>> getMyself(Principal principal) {
		return Mono.justOrEmpty(users.get(principal.getName()))
			.map(u -> ResponseEntity.ok(new User(u.email())))
			.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()));
	}
}
