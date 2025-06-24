package com.nhnacademy.gatewayservice.domain;

public record RefreshTokenResponseDto(
        String accessToken,
        String refreshToken
) {
}
