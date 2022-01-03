/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import org.gridsuite.gateway.endpoints.EndPointElementServer;
import org.gridsuite.gateway.endpoints.EndPointServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.ApplicationContext;
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

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.regex.Pattern;

import static org.gridsuite.gateway.GatewayConfig.END_POINT_SERVICE_NAME;
import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;
import static org.gridsuite.gateway.GatewayService.completeWithCode;
import static org.gridsuite.gateway.endpoints.EndPointElementServer.QUERY_PARAM_ID;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component
public class ElementAccessControllerGlobalPreFilter implements GlobalFilter, Ordered {

    private static final Logger LOGGER = LoggerFactory.getLogger(ElementAccessControllerGlobalPreFilter.class);

    private static final String ROOT_CATEGORY_REACTOR = "reactor.";

    private static final String DIRECTORY_ELEMENTS_ROOT_PATH = "elements";

    private final WebClient webClient;

    private final ApplicationContext applicationContext;

    public ElementAccessControllerGlobalPreFilter(ApplicationContext context, ServiceURIsConfig servicesURIsConfig, WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl(servicesURIsConfig.getDirectoryServerBaseUri()).build();
        this.applicationContext = context;
    }

    @Override
    public int getOrder() {
        // Before WebsocketRoutingFilter to control access
        return Ordered.LOWEST_PRECEDENCE - 2;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        RequestPath path = exchange.getRequest().getPath();

        // Filter only requests to the applications with this pattern : /v<number>/<appli_root_path>
        if (!Pattern.matches("/v(\\d)+/.*", path.value())) {
            return chain.filter(exchange);
        }

        // Is a controlled application ?
        String endPointServiceName = Objects.requireNonNull((String) (Objects.requireNonNull((Route) exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR)).getMetadata()).get(END_POINT_SERVICE_NAME));
        EndPointServer endPointServer = applicationContext.containsBean(endPointServiceName) ? (EndPointServer) applicationContext.getBean(endPointServiceName) : null;
        if (endPointServer == null || !endPointServer.hasElementsAccessControl()) {
            return chain.filter(exchange);
        }

        EndPointElementServer endPointElementServer = (EndPointElementServer) endPointServer;
        if (endPointElementServer.isNotControlledRootPath(path.elements().get(3).value())) {
            return chain.filter(exchange);
        }

        // Only allowed methods
        if (!endPointElementServer.isAllowedMethod(exchange.getRequest().getMethod())) {
            return completeWithCode(exchange, HttpStatus.FORBIDDEN);
        }

        // Elements creation ?
        if (Objects.requireNonNull(exchange.getRequest().getMethod()) == HttpMethod.POST
            && EndPointElementServer.getElementUuidIfExist(path) == null
        ) {
            return chain.filter(exchange);
        }

        List<UUID> elementUuids = endPointElementServer.getElementsUuids(exchange.getRequest());
        return elementUuids.isEmpty() ? completeWithCode(exchange, HttpStatus.FORBIDDEN) : isElementsAccessAllowed(exchange, chain, elementUuids);
    }

    private Mono<Void> isElementsAccessAllowed(ServerWebExchange exchange, GatewayFilterChain chain, List<UUID> elementUuids) {
        ServerHttpRequest httpRequest = exchange.getRequest();
        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        return webClient
            .head()
            .uri(uriBuilder -> uriBuilder
                .path(httpRequest.getPath().subPath(0, 3).value()) // version
                .path(DIRECTORY_ELEMENTS_ROOT_PATH)
                .queryParam(QUERY_PARAM_ID, elementUuids)
                .build()
            )
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
}

