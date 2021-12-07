/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;
import static org.gridsuite.gateway.GatewayService.completeWithCode;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component
public class DirectoryAccessRightsPreFilter implements GlobalFilter, Ordered {

    private static final Logger LOGGER = LoggerFactory.getLogger(DirectoryAccessRightsPreFilter.class);

    private static final String ROOT_CATEGORY_REACTOR = "reactor.";

    private static final Set<String> ALLOWED_HTTP_METHODS = Set.of(HttpMethod.GET.name(), HttpMethod.HEAD.name(),
        HttpMethod.PUT.name(), HttpMethod.POST.name(), HttpMethod.DELETE.name()
    );

    private static final String DIRECTORIES_ROOT_PATH = "directories";

    private static final String ELEMENTS_ROOT_PATH = "elements";

    private final WebClient webClient;

    public DirectoryAccessRightsPreFilter(ServicesURIsConfig servicesURIsConfig, WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl(servicesURIsConfig.getDirectoryServerBaseUri()).build();
    }

    @Override
    public int getOrder() {
        // Before WebsocketRoutingFilter to enforce authentication
        return Ordered.LOWEST_PRECEDENCE - 2;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        RequestPath path = exchange.getRequest().getPath();

        // Filter only requests to the directory server : /v*/directories/** or /v*/elements/** ?
        if (path.elements().size() < 4 || (
            !path.elements().get(3).value().equals(DIRECTORIES_ROOT_PATH)
                && !path.elements().get(3).value().equals(ELEMENTS_ROOT_PATH))
        ) {
            return chain.filter(exchange);
        }

        // Only allowed methods
        if (!ALLOWED_HTTP_METHODS.contains(exchange.getRequest().getMethodValue())) {
            return completeWithCode(exchange, HttpStatus.FORBIDDEN);
        }

        String rootPath = path.elements().get(3).value();
        switch (rootPath) {
            case DIRECTORIES_ROOT_PATH:
                if (path.elements().size() == 8 && isUuid(path.elements().get(5).value()) && path.elements().get(7).value().equals(ELEMENTS_ROOT_PATH)) {   // path = /v*/directories/{directoryUuid}/elements ?
                    return isDirectoryAccessAllowed(exchange, chain);
                } else {
                    return completeWithCode(exchange, HttpStatus.FORBIDDEN);
                }
            case ELEMENTS_ROOT_PATH:
                if (path.elements().size() == 4 ||                                                  // path = /v*/directories/elements ?
                    (path.elements().size() == 6 && isUuid(path.elements().get(5).value()))) {      // path = /v*/directories/elements/{elementUuid} ?
                    return isElementsAccessAllowed(exchange, chain);

                } else {
                    return completeWithCode(exchange, HttpStatus.FORBIDDEN);
                }
            default:
                return completeWithCode(exchange, HttpStatus.FORBIDDEN);
        }
    }

    private boolean isUuid(String uuid) {
        try {
            UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return true;
    }

    private Mono<Void> isDirectoryAccessAllowed(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest httpRequest = exchange.getRequest();
        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        return webClient
            .head()
            .uri(uriBuilder -> uriBuilder
                .path(httpRequest.getPath().subPath(0, 3).value())
                .path(ELEMENTS_ROOT_PATH)
                .queryParam("id", httpRequest.getPath().elements().get(5).value()).build())
            .header(HEADER_USER_ID, Objects.requireNonNull(httpHeaders.get(HEADER_USER_ID)).get(0))
            .exchangeToMono(response -> {
                switch (response.statusCode()) {
                    case OK:
                        return chain.filter(exchange);
                    case FORBIDDEN:
                        return completeWithCode(exchange, HttpStatus.FORBIDDEN);
                    default:
                        return response.createException().flatMap(Mono::error);
                }
            })
            .publishOn(Schedulers.boundedElastic())
            .log(ROOT_CATEGORY_REACTOR, Level.FINE);
    }

    private Mono<Void> isElementsAccessAllowed(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange);
    }
}

