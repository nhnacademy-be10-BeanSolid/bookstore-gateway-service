package com.nhnacademy.gatewayservice.filter;

import com.nhnacademy.gatewayservice.domain.TokenResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Map;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final SecretKey secretKey;
    private final WebClient.Builder webClientBuilder;

    public AuthorizationHeaderFilter(@Value("${jwt.secret}") String secret, WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.webClientBuilder = webClientBuilder;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            HttpCookie jwtCookie = request.getCookies().getFirst("accessToken");

            String jwt = null;
            Claims claims = null;
            boolean valid = false;

            if(jwtCookie != null) {
                jwt = jwtCookie.getValue();
                try {
                    claims = Jwts.parser()
                            .verifyWith(secretKey)
                            .build()
                            .parseSignedClaims(jwt)
                            .getPayload();
                    valid = true;
                } catch (Exception e) {
                    valid = false;
                }
            }

            if(valid  && claims != null) {
                // AccessToken이 유효한 경우
                String userId = claims.getSubject();
                ServerHttpRequest mutateRequest = request.mutate()
                        .header("X-USER-ID", userId)
                        .build();
                return chain.filter(exchange.mutate().request(mutateRequest).build());
            } else {
                // AccessToken이 없거나 만료된 경우
                HttpCookie refreshCookie = request.getCookies().getFirst("refreshToken");
                if(refreshCookie == null) {
                    return onError(exchange, "No RefreshToken in cookie");
                }
                String refreshToken = refreshCookie.getValue();

                // Auth-Service에 RefreshToken 새 Access AccessToken 요청
                return webClientBuilder
                        .build()
                        .post()
                        .uri("lb://auth-service/auth/refresh")
                        .bodyValue(Map.of("refreshToken", refreshToken))
                        .retrieve()
                        .bodyToMono(TokenResponse.class)
                        .flatMap(tokenResponse -> {
                            // 새 AccessToken과 RefreshToken을 쿠키에 반영
                            ServerHttpResponse response = exchange.getResponse();
                            ResponseCookie newAccessCookie = ResponseCookie.from("accessToken", tokenResponse.getAccessToken())
                                    .httpOnly(true)
                                    .path("/")
                                    .secure(true)
                                    .maxAge(60 * 60)
                                    .build();
                            ResponseCookie newRefreshCookie = ResponseCookie.from("refreshToken", tokenResponse.getRefreshToken())
                                    .httpOnly(true)
                                    .path("/")
                                    .secure(true)
                                    .maxAge(60 * 60 * 24 * 7)
                                    .build();
                            response.addCookie(newAccessCookie);
                            response.addCookie(newRefreshCookie);

                            // 새 AccessToken downstream 호출
                            Claims newClaims = Jwts.parser()
                                    .verifyWith(secretKey)
                                    .build()
                                    .parseSignedClaims(tokenResponse.getAccessToken())
                                    .getPayload();
                            String userId = newClaims.getSubject();
                            ServerHttpRequest mutateRequest = request.mutate()
                                    .header("X-USER-ID", userId)
                                    .build();
                            return chain.filter(exchange.mutate().request(mutateRequest).build());
                        })
                        .onErrorResume(e -> onError(exchange, "RefreshToken expired or invalid"));
            }
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    public static class Config {

    }
}
