package gratis.contoh.auth.catcher;


import java.util.concurrent.ExecutionException;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import gratis.contoh.auth.annotation.Authorize;
import gratis.contoh.auth.constant.AuthTypes;
import gratis.contoh.auth.exception.UnauthenticateException;
import gratis.contoh.auth.exception.UnauthorizeException;
import gratis.contoh.auth.service.AuthorizeValidator;
import reactor.core.publisher.Mono;

@Aspect
@Component
public class AuthorizeCatcher {
	
	@Pointcut("args(httpServletRequest,..)")
	private void httpServletRequest(ServerHttpRequest serverHttpRequest) {}
	
	@Pointcut("@annotation(authorize)")
	private void authorizeData(Authorize authorize) {}
	
	@Autowired
	private AuthorizeValidator validator;
	
	@Before("authorizeData(authorize) && httpServletRequest(request)")
	public void before(Authorize authorize, ServerHttpRequest request) 
			throws InterruptedException, ExecutionException {
		if (!(request instanceof ServerHttpRequest)) {
			throw new RuntimeException("request should be ServerHttpRequest");
		}
		
		String headerName = authorize.header();
		String authType = authorize.authType();
		String[] roles = authorize.roles();
		String module = authorize.module();
		String[] accessTypes = authorize.accessTypes();
		
		String headerValue = request.getHeaders().getFirst(headerName);
		
		if (headerValue != null) {
			boolean res = authorizeHeader(
					authType, headerValue, roles, module, accessTypes).toFuture().get();;
			
			if (!res) {
				throw new UnauthorizeException("you don't have permission to access this resource");
			}
				
		} else {
			throw new UnauthenticateException("please login to access this resource");
		}
	}
	
	private Mono<Boolean> authorizeHeader(
			String authType, 
			String token, 
			String[] roles, 
			String module, 
			String[] accessTypes) {
		switch (authType) {
			case AuthTypes.BEARER: {
				if (token.startsWith("Bearer ")) {
					return this.validator.verify(token.split(" ")[1], roles, module, accessTypes);				
				} else {
					return Mono.just(false);
				}
			}
			case AuthTypes.BASIC: {
				if (token.startsWith("Basic ")) {
					return this.validator.verify(token.split(" ")[1], roles, module, accessTypes);				
				} else {
					return Mono.just(false);
				}
			}
			default: {
				return this.validator.verify(token.split(" ")[1], roles, module, accessTypes);	
			}
		}
	}

}
