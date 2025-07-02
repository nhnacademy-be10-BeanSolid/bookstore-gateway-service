package com.nhnacademy.gatewayservice.filter;

import com.nhnacademy.gatewayservice.domain.TokenParseResponseDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationHeaderFilterTest {

    @Mock
    private WebClient.Builder webClientBuilder;
    @Mock
    private WebClient webClient;
    @Mock
    private WebClient.RequestBodyUriSpec uriSpec;
    @Mock
    private WebClient.RequestHeadersSpec<?> headersSpec;
    @Mock
    private WebClient.ResponseSpec responseSpec;
    @Mock
    private GatewayFilterChain filterChain;

    @InjectMocks
    private AuthorizationHeaderFilter filter;

    @Test
    void withoutAuthorizationHeader_shouldSkipFilter() {
        when(filterChain.filter(any())).thenReturn(Mono.empty());

        MockServerHttpRequest request = MockServerHttpRequest.get("/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilter gatewayFilter = filter.apply(new AuthorizationHeaderFilter.Config());
        Mono<Void> result = gatewayFilter.filter(exchange, filterChain);

        StepVerifier.create(result).verifyComplete();
        verify(filterChain).filter(exchange);  // 원본 Exchange 그대로 전달
    }

    @Test
    void withValidBearerHeader_shouldInjectXUserIdAndContinue() {
        String token = "validToken123";
        String userId = "user42";

        // WebClient 모킹 세팅
        when(webClientBuilder.build()).thenReturn(webClient);
        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri("lb://auth-service/auth/parse")).thenReturn(uriSpec);
        doReturn(headersSpec).when(uriSpec).bodyValue(token);
        when(headersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(TokenParseResponseDto.class))
                .thenReturn(Mono.just(new TokenParseResponseDto(userId, null)));
        when(filterChain.filter(any())).thenReturn(Mono.empty());

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("Authorization", "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilter gatewayFilter = filter.apply(new AuthorizationHeaderFilter.Config());
        Mono<Void> result = gatewayFilter.filter(exchange, filterChain);

        ArgumentCaptor<org.springframework.web.server.ServerWebExchange> captor =
                ArgumentCaptor.forClass(org.springframework.web.server.ServerWebExchange.class);

        StepVerifier.create(result).verifyComplete();
        verify(filterChain).filter(captor.capture());

        var mutatedExchange = captor.getValue();
        assertEquals(userId, mutatedExchange.getRequest().getHeaders().getFirst("X-USER-ID"));
    }

    @Test
    void withNonBearerHeader_shouldSkipFilter() {
        when(filterChain.filter(any())).thenReturn(Mono.empty());

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("Authorization", "Token abcdef")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilter gatewayFilter = filter.apply(new AuthorizationHeaderFilter.Config());
        Mono<Void> result = gatewayFilter.filter(exchange, filterChain);

        StepVerifier.create(result).verifyComplete();
        verify(filterChain).filter(exchange);  // "Bearer "이 아니므로 스킵
    }

    @Test
    void whenParsingFails_shouldSkipFilter() {
        String token = "invalidToken";

        when(webClientBuilder.build()).thenReturn(webClient);
        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri("lb://auth-service/auth/parse")).thenReturn(uriSpec);
        doReturn(headersSpec).when(uriSpec).bodyValue(token);
        when(headersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(TokenParseResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException("parse failed")));
        when(filterChain.filter(any())).thenReturn(Mono.empty());

        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header("Authorization", "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilter gatewayFilter = filter.apply(new AuthorizationHeaderFilter.Config());
        Mono<Void> result = gatewayFilter.filter(exchange, filterChain);

        StepVerifier.create(result).verifyComplete();
        verify(filterChain).filter(exchange);  // 파싱 실패 시 원본 Exchange 전달
    }

}
