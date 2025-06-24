package com.nhnacademy.gatewayservice.filter;

import com.nhnacademy.gatewayservice.domain.RefreshTokenResponseDto;
import com.nhnacademy.gatewayservice.domain.TokenParseResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationHeaderFilterTest {

    @Mock
    private WebClient.Builder webClientBuilder;
    @Mock
    private WebClient webClient;

    private AuthorizationHeaderFilter filter;

    @BeforeEach
    void setUp() {
        // lenient로 UnnecessaryStubbingException 방지
        lenient().when(webClientBuilder.build()).thenReturn(webClient);
        filter = new AuthorizationHeaderFilter(webClientBuilder);
    }

    @Test
    void shouldAddXUserIdHeaderWhenAccessTokenIsValid() {
        String accessToken = "validAccessToken";
        String userId = "user1";
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .cookie(new HttpCookie("accessToken", accessToken))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        // WebClient 체인 mock
        WebClient.RequestBodyUriSpec uriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec bodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = mock(WebClient.RequestHeadersSpec.class);
        WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri(anyString())).thenReturn(bodySpec);
        doReturn(headersSpec).when(bodySpec).bodyValue(any());
        when(headersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.just(new TokenParseResponseDto(userId, null))
        );

        filter.apply(new AuthorizationHeaderFilter.Config()).filter(exchange, chain).block();

        assertThat(exchange.getRequest().getHeaders().getFirst("X-USER-ID")).isEqualTo(userId);
        verify(chain, times(1)).filter(any());
    }

    @Test
    void shouldAddXUserIdHeaderWhenAccessTokenIsExpiredAndRefreshTokenSucceeds() {
        String expiredAccessToken = "expiredAccessToken";
        String refreshToken = "refreshToken";
        String newAccessToken = "newAccessToken";
        String newRefreshToken = "newRefreshToken";
        String userId = "user2";
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .cookie(new HttpCookie("accessToken", expiredAccessToken))
                .cookie(new HttpCookie("refreshToken", refreshToken))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        // WebClient 체인 mock (파싱 실패, refresh 성공, 새 토큰 파싱 성공)
        WebClient.RequestBodyUriSpec uriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec bodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = mock(WebClient.RequestHeadersSpec.class);

        WebClient.ResponseSpec parseFailSpec = mock(WebClient.ResponseSpec.class);
        WebClient.ResponseSpec refreshSuccessSpec = mock(WebClient.ResponseSpec.class);
        WebClient.ResponseSpec parseSuccessSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri(contains("/auth/parse"))).thenReturn(bodySpec);
        when(uriSpec.uri(contains("/auth/refresh"))).thenReturn(bodySpec);

        doReturn(headersSpec).when(bodySpec).bodyValue(any());
        when(headersSpec.retrieve())
                .thenReturn(parseFailSpec)      // 첫 번째: accessToken 파싱 실패
                .thenReturn(refreshSuccessSpec) // 두 번째: refreshToken 성공
                .thenReturn(parseSuccessSpec);  // 세 번째: 새 accessToken 파싱 성공

        when(parseFailSpec.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.error(new RuntimeException("expired"))
        );
        when(refreshSuccessSpec.bodyToMono(RefreshTokenResponseDto.class)).thenReturn(
                Mono.just(new RefreshTokenResponseDto(newAccessToken, newRefreshToken))
        );
        when(parseSuccessSpec.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.just(new TokenParseResponseDto(userId, null))
        );

        filter.apply(new AuthorizationHeaderFilter.Config()).filter(exchange, chain).block();

        assertThat(exchange.getRequest().getHeaders().getFirst("X-USER-ID")).isEqualTo(userId);
        verify(chain, times(1)).filter(any());
    }

    @Test
    void shouldPassThroughWhenNoTokensPresent() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/test").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        filter.apply(new AuthorizationHeaderFilter.Config()).filter(exchange, chain).block();

        assertThat(exchange.getRequest().getHeaders().getFirst("X-USER-ID")).isNull();
        verify(chain, times(1)).filter(any());
    }

    @Test
    void shouldPassThroughWhenRefreshTokenFails() {
        String expiredAccessToken = "expiredAccessToken";
        String refreshToken = "refreshToken";
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .cookie(new HttpCookie("accessToken", expiredAccessToken))
                .cookie(new HttpCookie("refreshToken", refreshToken))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        // WebClient 체인 mock (파싱 실패, refresh 실패)
        WebClient.RequestBodyUriSpec uriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec bodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = mock(WebClient.RequestHeadersSpec.class);

        WebClient.ResponseSpec parseFailSpec = mock(WebClient.ResponseSpec.class);
        WebClient.ResponseSpec refreshFailSpec = mock(WebClient.ResponseSpec.class);

        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri(contains("/auth/parse"))).thenReturn(bodySpec);
        when(uriSpec.uri(contains("/auth/refresh"))).thenReturn(bodySpec);

        doReturn(headersSpec).when(bodySpec).bodyValue(any());
        when(headersSpec.retrieve())
                .thenReturn(parseFailSpec)      // 첫 번째: accessToken 파싱 실패
                .thenReturn(refreshFailSpec);   // 두 번째: refreshToken 실패

        when(parseFailSpec.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.error(new RuntimeException("expired"))
        );
        when(refreshFailSpec.bodyToMono(RefreshTokenResponseDto.class)).thenReturn(
                Mono.error(new RuntimeException("refreshToken expired"))
        );

        // 예외가 발생해도 통과해야 하므로 block()에서 예외 발생하지 않음
        filter.apply(new AuthorizationHeaderFilter.Config()).filter(exchange, chain).block();

        assertThat(exchange.getRequest().getHeaders().getFirst("X-USER-ID")).isNull();
        verify(chain, times(1)).filter(any());
    }

    @Test
    void shouldPassThroughWhenAccessTokenParsingFailsAfterRefreshTokenReissue() {
        String expiredAccessToken = "expiredAccessToken";
        String refreshToken = "refreshToken";
        String newAccessToken = "newAccessToken";
        String newRefreshToken = "newRefreshToken";
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .cookie(new HttpCookie("accessToken", expiredAccessToken))
                .cookie(new HttpCookie("refreshToken", refreshToken))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        // WebClient 체인 mock
        WebClient.RequestBodyUriSpec uriSpec = mock(WebClient.RequestBodyUriSpec.class);
        WebClient.RequestBodySpec bodySpec = mock(WebClient.RequestBodySpec.class);
        WebClient.RequestHeadersSpec<?> headersSpec = mock(WebClient.RequestHeadersSpec.class);

        WebClient.ResponseSpec parseFailSpec1 = mock(WebClient.ResponseSpec.class); // initial accessToken parse fail
        WebClient.ResponseSpec refreshSuccessSpec = mock(WebClient.ResponseSpec.class); // refreshToken success
        WebClient.ResponseSpec parseFailSpec2 = mock(WebClient.ResponseSpec.class); // new accessToken parse fail

        when(webClient.post()).thenReturn(uriSpec);
        when(uriSpec.uri(contains("/auth/parse"))).thenReturn(bodySpec);
        when(uriSpec.uri(contains("/auth/refresh"))).thenReturn(bodySpec);

        doReturn(headersSpec).when(bodySpec).bodyValue(any());
        when(headersSpec.retrieve())
                .thenReturn(parseFailSpec1)      // 1. accessToken 파싱 실패
                .thenReturn(refreshSuccessSpec)  // 2. refreshToken 재발급 성공
                .thenReturn(parseFailSpec2);     // 3. 새 accessToken 파싱 실패

        when(parseFailSpec1.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.error(new RuntimeException("expired"))
        );
        when(refreshSuccessSpec.bodyToMono(RefreshTokenResponseDto.class)).thenReturn(
                Mono.just(new RefreshTokenResponseDto(newAccessToken, newRefreshToken))
        );
        when(parseFailSpec2.bodyToMono(TokenParseResponseDto.class)).thenReturn(
                Mono.error(new RuntimeException("new accessToken parse failed"))
        );

        filter.apply(new AuthorizationHeaderFilter.Config()).filter(exchange, chain).block();

        // 새 accessToken 파싱도 실패했으므로 X-USER-ID 헤더가 없어야 함
        assertThat(exchange.getRequest().getHeaders().getFirst("X-USER-ID")).isNull();
        verify(chain, times(1)).filter(any());
    }

}
