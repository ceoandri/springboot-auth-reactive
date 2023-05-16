package gratis.contoh.auth.service;

import reactor.core.publisher.Mono;

public interface AuthorizeValidator {
	
	public Mono<Boolean> verify(
			String headerValue, String[] roles, String module, String[] accessType);

}
