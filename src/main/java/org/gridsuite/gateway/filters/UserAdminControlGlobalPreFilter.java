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

import java.util.List;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Etienne Homer <etienne.homer at rte-france.com>
 *
 *  This filter executes after other filters in the chain (as determined by its order),
 *  allowing other filters to reject invalid requests before reaching this point.
 *  The primary purpose of this filter is to record successful user connections rather than
 *  to reject requests - except missing user ID which results in UNAUTHORIZED.
 */
@Component
public class UserAdminControlGlobalPreFilter extends AbstractGlobalPreFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserAdminControlGlobalPreFilter.class);

    public UserAdminControlGlobalPreFilter(UserAdminService userAdminService) {
        super(userAdminService);
    }

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        List<String> maybeSubList = httpHeaders.get(HEADER_USER_ID);

        if (maybeSubList != null) {
            String sub = maybeSubList.get(0);
            // Record the connection with isConnectionAccepted=true
            // and continue with the filter chain regardless of the result
            userAdminService.userRecordConnection(sub, true).subscribe();
            return chain.filter(exchange);
        }

        return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 3;
    }
}
