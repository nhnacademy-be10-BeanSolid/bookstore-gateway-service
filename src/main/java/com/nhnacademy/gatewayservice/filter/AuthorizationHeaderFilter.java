package com.nhnacademy.gatewayservice.filter;

import com.nhnacademy.gatewayservice.domain.TokenParseResponseDto;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private static final String X_USER_ID_HEADER = "X-USER-ID";

    private final WebClient.Builder webClientBuilder;

    public AuthorizationHeaderFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String authHeader = request.getHeaders().getFirst("Authorization");
            if(authHeader != null && authHeader.startsWith("Bearer ")) {
                String accessToken = StringUtils.removeStart(authHeader, "Bearer ");
                log.debug("Authorization 헤더에서 토큰 추출, 파싱 시도");
                return webClientBuilder.build()
                        .post()
                        .uri("lb://auth-service/auth/parse")
                        .bodyValue(accessToken)
                        .retrieve()
                        .bodyToMono(TokenParseResponseDto.class)
                        .flatMap(parseResponse -> {
                            log.info("accessToken 파싱 성공, userId: {}", parseResponse.username());
                            ServerHttpRequest mutatedRequest = request.mutate()
                                    .header(X_USER_ID_HEADER, parseResponse.username())
                                    .build();
                            return chain.filter(exchange.mutate().request(mutatedRequest).build());
                        })
                        .onErrorResume(e -> {
                            log.warn("accessToken 파싱 실패: {}, 인증 없이 통과", e.getMessage());

                            return chain.filter(exchange);
                        });
            } else {
                log.debug("Authorization 헤더 없음, 인증 없이 통과");
                return chain.filter(exchange);
            }
        };
    }

    public static class Config {}
}
