package com.nhnacademy.gatewayservice.filter;

import com.nhnacademy.gatewayservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.gatewayservice.domain.TokenParseResponseDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private static final String X_USER_ID_HEADER = "X-USER-ID";

    private final WebClient.Builder webClientBuilder;

    @Value("${custom.security.jwt.access-token-expiration}")
    private int accessTokenExpiration;

    @Value("${custom.security.jwt.refresh-token-expiration}")
    private int refreshTokenExpiration;

    public AuthorizationHeaderFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            HttpCookie accessTokenCookie = request.getCookies().getFirst("accessToken");

            if(accessTokenCookie != null) {
                String accessToken = accessTokenCookie.getValue();
                log.debug("accessToken 존재, 파싱 시도");
                return parseTokenAndForward(accessToken, request, exchange, chain)
                        .onErrorResume(e -> {
                            log.warn("accessToken 파싱 실패: {}, refreshToken 재발급 시도", e.getMessage());
                            return tryRefreshTokenAndForward(request, exchange, chain);
                        });
            } else {
                log.debug("accessToken 없음, refreshToken 확인");
                return tryRefreshTokenAndForward(request, exchange, chain);
            }
        };
    }

    private Mono<Void> parseTokenAndForward(String token, ServerHttpRequest request, ServerWebExchange exchange, GatewayFilterChain chain) {
        return webClientBuilder.build()
                .post()
                .uri("lb://auth-service/auth/parse")
                .bodyValue(token)
                .retrieve()
                .bodyToMono(TokenParseResponseDto.class)
                .flatMap(parseResponse -> {
                    log.info("accessToken 파싱 성공, userId: {}", parseResponse.username());
                    ServerHttpRequest mutatedRequest = addUserIdHeader(request, parseResponse.username());
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                });
    }

    private Mono<Void> tryRefreshTokenAndForward(ServerHttpRequest request, ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpCookie refreshTokenCookie = request.getCookies().getFirst("refreshToken");
        if(refreshTokenCookie == null) {
            log.debug("refreshToken 없음, 인증 없이 통과");
            return chain.filter(exchange);
        }
        String refreshToken = refreshTokenCookie.getValue();
        log.debug("refreshToken 존재, accessToken 재발급 시도");
        return webClientBuilder.build()
                .post()
                .uri("lb://auth-service/auth/refresh")
                .bodyValue(refreshToken)
                .retrieve()
                .bodyToMono(RefreshTokenResponseDto.class)
                .flatMap(tokenResponse -> {
                    log.info("accessToken 재발급 성공");
                    addTokenCookies(exchange.getResponse(), tokenResponse);
                    return parseTokenAndForward(tokenResponse.accessToken(), request, exchange, chain)
                            .onErrorResume(e -> {
                                log.warn("재발급된 accessToken 파싱 실패: {}", e.getMessage());
                                return chain.filter(exchange);
                            });
                })
                .onErrorResume(e -> {
                    log.warn("refreshToken 재발급 실패: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private ServerHttpRequest addUserIdHeader(ServerHttpRequest request, String userId) {
        return request.mutate()
                .header(X_USER_ID_HEADER, userId)
                .build();
    }

    private void addTokenCookies(ServerHttpResponse response, RefreshTokenResponseDto tokenResponse) {
        ResponseCookie accessCookie = ResponseCookie.from("accessToken", tokenResponse.accessToken())
                .httpOnly(true).secure(true).path("/").maxAge(accessTokenExpiration).build();
        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", tokenResponse.refreshToken())
                .httpOnly(true).secure(true).path("/").maxAge(refreshTokenExpiration).build();
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }

    public static class Config {}
}
