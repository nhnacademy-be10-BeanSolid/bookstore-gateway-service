package com.nhnacademy.gatewayservice.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.cors.reactive.CorsWebFilter;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CorsConfigTest {

    private CorsConfig corsConfig;

    @BeforeEach
    void setUp() {
        corsConfig = new CorsConfig();
    }

    @Test
    void corsWebFilterBeanIsCreated() {
        CorsWebFilter corsWebFilter = corsConfig.corsWebFilter();
        assertNotNull(corsWebFilter, "CorsWebFilter bean should not be null");
    }
}