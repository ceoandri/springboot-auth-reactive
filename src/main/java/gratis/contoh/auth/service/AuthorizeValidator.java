package gratis.contoh.auth.service;

import reactor.core.publisher.Mono;

public interface AuthorizeValidator {
	
	public Mono<Boolean> isAuthenticate(String headerValue);
	
	public Mono<Boolean> isAuthorize(
			String headerValue, String[] roles, String module, String[] accessType);

}
