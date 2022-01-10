/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public abstract class AbstractGlobalPreFilter implements GlobalFilter, Ordered {

    protected Mono<Void> completeWithCode(ServerWebExchange exchange, HttpStatus code) {
        exchange.getResponse().setStatusCode(code);
        if ("websocket".equalsIgnoreCase(exchange.getRequest().getHeaders().getUpgrade())) {
            // Force the connection to close for websockets handshakes to workaround apache
            // httpd reusing the connection for all subsequent requests in this connection.
            exchange.getResponse().getHeaders().set(HttpHeaders.CONNECTION, "close");
        }
        return exchange.getResponse().setComplete();
    }

}
