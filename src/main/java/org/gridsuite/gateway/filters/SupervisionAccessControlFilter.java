/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
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
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

/**
 * A global pre-filter that controls access to supervision endpoints in the API gateway.
 *
 * This filter inspects the incoming request path and blocks access to specific supervision
 * endpoints based on a predefined pattern. The filter is designed to enhance security by
 * restricting access to potentially sensitive supervision functionalities.
 *
 * The filter blocks access to paths matching the following pattern:
 * {@code /v<number>/supervision} or {@code /v<number>/supervision/<any-sub-path>}
 * where {@code <number>} can be any positive integer representing the API version.
 *
 * Examples of blocked paths:
 * - /v1/supervision
 * - /v2/supervision/
 * - /v10/supervision/health
 * - /v999/supervision/metrics
 *
 * When a matching path is detected, the filter responds with a 403 Forbidden status.
 *
 * @author Achour BERRAHMA <achour.berrahma at rte-france.com>
 */
@Component
public class SupervisionAccessControlFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SupervisionAccessControlFilter.class);
    private static final Pattern SUPERVISION_PATTERN = Pattern.compile("^/v\\d+/supervision(/.*)?$");
    public static final String ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED = "{}: 403 Forbidden, Access to supervision endpoint is not allowed";

    public SupervisionAccessControlFilter(UserAdminService userAdminService) {
        super(userAdminService);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (SUPERVISION_PATTERN.matcher(path).matches()) {
            LOGGER.info(ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED,
                    exchange.getRequest().getPath());
            return completeWithError(exchange, HttpStatus.FORBIDDEN);
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        // Execute after TokenValidatorGlobalPreFilter and UserAdminControlGlobalPreFilter
        return Ordered.LOWEST_PRECEDENCE - 2;
    }
}
