package com.nhnacademy.gatewayservice.domain;

import java.util.List;

public record TokenParseResponseDto(
        String username,
        List<String> authorities
) {
}
