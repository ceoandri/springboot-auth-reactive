package gratis.contoh.auth.catcher;

import java.util.List;
import java.util.concurrent.ExecutionException;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import gratis.contoh.auth.annotation.Authorize;
import gratis.contoh.auth.configuration.ServerWebExchangeContextFilter;
import gratis.contoh.auth.constant.AuthTypes;
import gratis.contoh.auth.exception.UnauthenticateException;
import gratis.contoh.auth.exception.UnauthorizeException;
import gratis.contoh.auth.service.AuthorizeValidator;
import reactor.core.publisher.Mono;

@Aspect
@Component
public class AuthorizeCatcher {
	@Pointcut("@annotation(authorize)")
	private void authorizeData(Authorize authorize) {}
	
	@Autowired
	private AuthorizeValidator validator;
	
	@Before("authorizeData(authorize)")
    public void before(Authorize authorize) 
    		throws UnauthenticateException, UnauthorizeException, InterruptedException, ExecutionException  {
		ServerWebExchange exchange = ServerWebExchangeContextFilter.serverWebExchangeThreadLocal.get();
        ServerHttpRequest request = exchange.getRequest();

        String headerName = authorize.header();
		String authType = authorize.authType();
		String[] roles = authorize.roles();
		String module = authorize.module();
		String[] accessTypes = authorize.accessTypes();
		
		HttpHeaders headers = request.getHeaders();
		List<String> headersStr = headers.get(headerName);
		if (headersStr == null || headersStr.size() == 0) {
			throw new UnauthenticateException("please login to access this resource");
		}
		
		String headerValue = headersStr.get(0);
		
		if (headerValue != null) {
			if (!this.validator.isAuthenticate(headerValue).toFuture().get()) {
				throw new UnauthenticateException("please login to access this resource");
			}
			
			boolean isAuthorize = authorizeHeader(
					authType, headerValue, roles, module, accessTypes).toFuture().get();
			
			if (!isAuthorize) {
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
					return this.validator.isAuthorize(token.split(" ")[1], roles, module, accessTypes);				
				} else {
					return Mono.just(false);
				}
			}
			case AuthTypes.BASIC: {
				if (token.startsWith("Basic ")) {
					return this.validator.isAuthorize(token.split(" ")[1], roles, module, accessTypes);				
				} else {
					return Mono.just(false);
				}
			}
			default: {
				return this.validator.isAuthorize(token, roles, module, accessTypes);	
			}
		}
	}

}
