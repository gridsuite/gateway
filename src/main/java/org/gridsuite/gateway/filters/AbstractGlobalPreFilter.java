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
     * Completes the exchange with the specified HTTP status code.
     *
     * IMPORTANT NOTE: This method is currently called only when authentication or authorization fails
     * in the filter chain. Therefore, we record a failed connection attempt (isConnectionAccepted=false)
     * here to track unsuccessful login attempts. If the usage of this method changes in the future
     * (e.g., if it's called for non-auth failures), this implementation should be reviewed.
     */
    protected Mono<Void> completeWithCode(ServerWebExchange exchange, HttpStatus code) {
        exchange.getResponse().setStatusCode(code);
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
            return userAdminService.userRecordConnection(sub, false)
                    .onErrorResume(error -> {
                        LOGGER.warn("Failed to record failed connection for user {}: {}", sub, error.getMessage());
                        return Mono.empty();
                    })
                    .then(exchange.getResponse().setComplete());
        }
        return exchange.getResponse().setComplete();
    }

}
