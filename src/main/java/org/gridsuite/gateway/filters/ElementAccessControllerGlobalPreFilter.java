/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway.filters;

import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component
public class ElementAccessControllerGlobalPreFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ElementAccessControllerGlobalPreFilter.class);

    @Override
    public int getOrder() {
        // Before WebsocketRoutingFilter to control access
        return Ordered.LOWEST_PRECEDENCE - 2;
    }

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());
        //TODO: the control is disabled for the moment, it will be processed in another US. For more details  contact slimane
        return chain.filter(exchange);
    }
}

