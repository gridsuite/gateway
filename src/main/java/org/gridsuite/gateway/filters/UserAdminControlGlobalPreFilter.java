/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import lombok.NonNull;
import org.gridsuite.gateway.services.UserAdminService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Etienne Homer <etienne.homer at rte-france.com>
 */
@Component
public class UserAdminControlGlobalPreFilter extends AbstractGlobalPreFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserAdminControlGlobalPreFilter.class);

    private UserAdminService userAdminService;

    public UserAdminControlGlobalPreFilter(UserAdminService userAdminService) {
        this.userAdminService = userAdminService;
    }

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        String sub = Objects.requireNonNull(httpHeaders.get(HEADER_USER_ID)).get(0);

        return userAdminService.userExists(sub).flatMap(userExist ->  Boolean.TRUE.equals(userExist) ? chain.filter(exchange) : completeWithCode(exchange, HttpStatus.FORBIDDEN));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 2;
    }
}
