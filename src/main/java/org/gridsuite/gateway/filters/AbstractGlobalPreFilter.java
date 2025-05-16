/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.gridsuite.gateway.services.UserAdminService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public abstract class AbstractGlobalPreFilter implements GlobalFilter, Ordered {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractGlobalPreFilter.class);

    protected final UserAdminService userAdminService;

    protected AbstractGlobalPreFilter(UserAdminService userAdminService) {
        this.userAdminService = userAdminService;
    }

    /**
     * Completes the exchange with the specified HTTP error status code and records failed connection attempts.
     *
     * IMPORTANT NOTE: This method is intended only for authentication or authorization failures
     * in the filter chain. It records a failed connection attempt (isConnectionAccepted=false)
     * to track unsuccessful login attempts. If called with non-error status codes, an
     * IllegalArgumentException will be thrown.
     *
     * @param exchange The server web exchange
     * @param status The HTTP error status to return to the client
     * @return A Mono that completes when the response has been sent
     * @throws IllegalArgumentException if called with a non-error status code
     */
    protected Mono<Void> completeWithError(ServerWebExchange exchange, HttpStatus status) {
        // Ensure we're only using this method with error status codes
        if (!status.isError()) {
            LOGGER.warn("completeWithError was called with a non-error status code: {}. " +
                    "This method is intended for error responses only.", status);
        }

        exchange.getResponse().setStatusCode(status);
        if ("websocket".equalsIgnoreCase(exchange.getRequest().getHeaders().getUpgrade())) {
            // Force the connection to close for websockets handshakes to workaround apache
            // httpd reusing the connection for all subsequent requests in this connection.
            exchange.getResponse().getHeaders().set(HttpHeaders.CONNECTION, "close");
        }

        // Record failed connection attempt if user ID is present
        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        List<String> maybeSubList = httpHeaders.get(HEADER_USER_ID);

        if (maybeSubList != null && !maybeSubList.isEmpty()) {
            String sub = maybeSubList.getFirst();
            userAdminService.userRecordConnection(sub, false).subscribe();
        }
        return exchange.getResponse().setComplete();
    }

}
