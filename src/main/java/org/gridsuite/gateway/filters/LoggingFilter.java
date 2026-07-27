/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.gridsuite.gateway.services.UserAdminService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.Arrays;

/**
 * @author Radouane KHOUADRI <redouane.khouadi_externe at rte-france.com>
 */
@Component
public class LoggingFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingFilter.class);

    private static final String[] ALLOWED_PATHS = {
        "/study/",
        "/study-config/",
        "/study-notification/",
        "/config/",
        "/config-notification/",
        "/explore/",
        "/directory-notification/",
        "/dynamic-mapping/",
        "/user-admin/",
        "/monitor/",
        "/monitor-notification/"
    };

    protected LoggingFilter(UserAdminService userAdminService) {
        super(userAdminService);
    }

    /**
     * This filter logs an error when a request targets non-allowed backend services directly through the gateway.
     * Its purpose is to verify if any requests to deprecated services are still routed through the gateway before removing them.
     *
     * NOTE: This filter is temporary and will be deleted after verifying that no unauthorized requests are made
     * to the restricted services during the migration process.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestPath = exchange.getRequest().getPath().toString();

        boolean isAllowedPath = Arrays.stream(ALLOWED_PATHS)
                .anyMatch(requestPath::startsWith);

        if (!isAllowedPath) {
            LOGGER.error("Unauthorized access to restricted backend service. path='{}', method='{}', clientIp='{}'.",
                    requestPath,
                    exchange.getRequest().getMethod(),
                    exchange.getRequest().getRemoteAddress());
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
