/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.gridsuite.gateway.filters.TokenValidatorGlobalPreFilter;
import org.gridsuite.gateway.filters.UserAdminControlGlobalPreFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        // case-server chosen without reason for this test, just to use a prefix
        properties = {"powsybl.services.case-server.base-uri=http://localhost:${wiremock.server.port}/prefix"})
@AutoConfigureWireMock(port = 0)
class BaseUriTest {

    // Mock the filters that require setup and just get in the way of this test
    @MockitoBean
    TokenValidatorGlobalPreFilter unusedTokenValidatorGlobalPreFilter;
    @MockitoBean
    UserAdminControlGlobalPreFilter unusedUserAdminControlGlobalPreFilter;

    @Autowired
    private WebTestClient webClient;

    @Test
    void testBaseUriPrefix() {

        mockFilterAsNoOp(unusedTokenValidatorGlobalPreFilter);
        mockFilterAsNoOp(unusedUserAdminControlGlobalPreFilter);

        stubFor(get(urlEqualTo("/prefix/test")).willReturn(aResponse().withBody("prefixtest")));

        webClient.get()
                .uri("/case/test")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("prefixtest");
    }

    private void mockFilterAsNoOp(GlobalFilter globalFilter) {
        when(globalFilter.filter(any(), any())).thenAnswer(
            inv -> {
                GatewayFilterChain chain = inv.getArgument(1);
                ServerWebExchange exchange = inv.getArgument(0);
                return chain.filter(exchange);
            });
    }
}
