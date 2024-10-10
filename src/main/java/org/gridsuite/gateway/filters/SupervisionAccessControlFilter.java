/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Achour BERRAHMA <achour.berrahma at rte-france.com>
 */
@Component
public class SupervisionAccessControlFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SupervisionAccessControlFilter.class);
    private static final String SUPERVISION_PATH = "supervision";
    public static final String ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED = "{}: 403 Forbidden, Access to supervision endpoint is not allowed";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter: {}", getClass().getSimpleName());

        String path = exchange.getRequest().getURI().getPath();
        if (path.toLowerCase().contains(SUPERVISION_PATH)) {
            LOGGER.info(ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED,
                    exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.FORBIDDEN);
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        // Execute after TokenValidatorGlobalPreFilter and UserAdminControlGlobalPreFilter
        return Ordered.LOWEST_PRECEDENCE - 2;
    }
}
