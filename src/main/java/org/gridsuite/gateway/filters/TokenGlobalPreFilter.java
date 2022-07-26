/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import lombok.AllArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import com.google.common.base.Strings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


import static org.gridsuite.gateway.config.GatewayConfig.HEADER_USER_ID;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
@Slf4j
@AllArgsConstructor
public class TokenGlobalPreFilter extends AbstractGlobalPreFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .filter(c -> c.getAuthentication() != null)
                .flatMap(c -> {
                    Authentication loggedInUser = c.getAuthentication();
                    String username = loggedInUser.getName();
                    if (Strings.isNullOrEmpty(username)) {
                        Mono.error(
                                new AccessDeniedException("Invalid token. User is not present in token.")
                        );
                        log.info("{}: Invalid token. User is not present in token.", exchange.getRequest().getPath());
                        return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
                    }

                    if (exchange.getRequest().getHeaders().get("Authorization") == null && exchange.getRequest().getQueryParams().get("access_token") == null) {
                        log.info("{}: 401 Unauthorized, Authorization header or access_token query parameter is required", exchange.getRequest().getPath());
                        return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
                    }

                    ServerHttpRequest request = exchange.getRequest().mutate()
                            .header(HEADER_USER_ID, username).build();

                    return chain.filter(exchange.mutate().request(request).build());
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        //The smaller the value, the more priority is given to execution
        return Ordered.LOWEST_PRECEDENCE - 3;
    }
}

