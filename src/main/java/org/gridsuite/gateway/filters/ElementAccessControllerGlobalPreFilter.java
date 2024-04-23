/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway.filters;

import lombok.NonNull;
import org.gridsuite.gateway.ServiceURIsConfig;
import org.gridsuite.gateway.dto.AccessControlInfos;
import org.gridsuite.gateway.endpoints.EndPointElementServer;
import org.gridsuite.gateway.endpoints.EndPointServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.regex.Pattern;

import static org.gridsuite.gateway.GatewayConfig.END_POINT_SERVICE_NAME;
import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;
import static org.gridsuite.gateway.endpoints.EndPointElementServer.QUERY_PARAM_IDS;
import static org.springframework.http.HttpStatus.*;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component
public class ElementAccessControllerGlobalPreFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ElementAccessControllerGlobalPreFilter.class);

    private static final String ROOT_CATEGORY_REACTOR = "reactor.";
    private static final String ELEMENTS_ROOT_PATH = "elements";
    private static final Pattern PATH_API_VERSION = Pattern.compile("^/v(\\d)+/.*");

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
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());

        RequestPath path = exchange.getRequest().getPath();

        // Filter only requests to the endpoint servers with this pattern: /v<number>/<appli_root_path>
        if (!PATH_API_VERSION.matcher(path.value()).matches()) {
            return chain.filter(exchange);
        }

        // Is an elements' endpoint with controlled access?
        final EndPointServer endPointServer = Optional.ofNullable((Route) exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR))
                .map(Route::getMetadata)
                .map(metadata -> (String) metadata.get(END_POINT_SERVICE_NAME))
                .map(endPointServiceName -> applicationContext.containsBean(endPointServiceName) ? (EndPointServer) applicationContext.getBean(endPointServiceName) : null)
                .orElse(null);
        if (!(endPointServer instanceof EndPointElementServer endPointElementServer)) {
            return chain.filter(exchange);
        }

        // Is a root path with controlled access?
        if (endPointElementServer.isNotControlledRootPath(path.elements().get(3).value())) {
            return chain.filter(exchange);
        }

        // Is a method allowed?
        if (!endPointElementServer.isAllowedMethod(exchange.getRequest().getMethod())) {
            return completeWithCode(exchange, FORBIDDEN);
        }

        return endPointElementServer.getAccessControlInfos(exchange.getRequest())
                                    .map(controlInfos -> isAccessAllowed(exchange, chain, controlInfos))
                                    .orElseGet(() -> completeWithCode(exchange, FORBIDDEN));
    }

    private Mono<Void> isAccessAllowed(ServerWebExchange exchange, GatewayFilterChain chain, AccessControlInfos accessControlInfos) {
        ServerHttpRequest httpRequest = exchange.getRequest();
        HttpHeaders httpHeaders = exchange.getRequest().getHeaders();
        return webClient
            .head()
            .uri(uriBuilder -> uriBuilder
                .path(httpRequest.getPath().subPath(0, 3).value()) // version
                .path(ELEMENTS_ROOT_PATH)
                .queryParam(QUERY_PARAM_IDS, accessControlInfos.getElementUuids())
                .build()
            )
            .header(HEADER_USER_ID, Objects.requireNonNull(httpHeaders.get(HEADER_USER_ID)).get(0))
            .exchangeToMono(response -> {
                HttpStatusCode httpStatusCode = response.statusCode();
                if (httpStatusCode.equals(OK)) {
                    return chain.filter(exchange);
                } else if (httpStatusCode.equals(NOT_FOUND)) {
                    return completeWithCode(exchange, NOT_FOUND);
                } else if (httpStatusCode.equals(FORBIDDEN)) {
                    return completeWithCode(exchange, FORBIDDEN);
                }
                return response.createException().flatMap(Mono::error);
            })
            .publishOn(Schedulers.boundedElastic())
            .log(ROOT_CATEGORY_REACTOR, Level.FINE);
    }
}

