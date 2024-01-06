package gratis.contoh.auth.configuration;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ServerWebExchangeContextFilter implements WebFilter {

    public static final ThreadLocal<ServerWebExchange> serverWebExchangeThreadLocal = new ThreadLocal<>();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        serverWebExchangeThreadLocal.set(exchange);
        return chain.filter(exchange).doFinally(signalType -> serverWebExchangeThreadLocal.remove());
    }
}