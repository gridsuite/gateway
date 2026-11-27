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
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Pattern;

/**
 * A global pre-filter that controls access to supervision endpoints in the API gateway.
 *
 * This filter inspects the incoming request path and blocks access to specific supervision
 * endpoints based on a predefined pattern. The filter is designed to enhance security by
 * restricting access to potentially sensitive supervision functionalities.
 *
 * The filter blocks access to paths whose first segment is {@code supervision}, or whose
 * second segment is {@code supervision} and the first one is a version segment such as
 * {@code v<number>}. It relies on {@link ServerWebExchange#getRequest()}'s already-parsed
 * {@link org.springframework.http.server.RequestPath} (a {@link PathContainer}), whose
 * {@link PathContainer.PathSegment#valueToMatch()} strips matrix parameters (the part of a
 * segment starting at {@code ;}) and decodes percent-escapes exactly once. Using the raw
 * {@code URI} path and re-parsing it here would decode percent-escapes a second time and
 * break ordinary requests containing a literal {@code %} (e.g. {@code /v1/studies/100%25}).
 *
 * This position-based check (segment 0, or segment 1 right after a version segment) assumes
 * that every proxied service's {@code base-uri} has no path component (only
 * {@code scheme://host[:port]}). {@code EndPointServer.getRoute()} strips the
 * {@code /{endpointName}} prefix and re-prepends the service's {@code base-uri} path (via its
 * {@code prefixPath} filter) before this filter runs; if a {@code base-uri} ever gets a path
 * component (e.g. {@code http://host/some-prefix}), {@code supervision} would be pushed to a
 * deeper segment and this filter would no longer catch it. Keep all {@code base-uri} values
 * path-less (see {@code ServiceURIsConfig}) to preserve this guarantee.
 *
 * Examples of blocked paths:
 * - /v1/supervision
 * - /v2/supervision/
 * - /v10/supervision/health
 * - /v999/supervision/metrics
 * - /supervision/filters
 * - /v1/supervision;x/studies
 *
 * When a matching path is detected, the filter responds with a 403 Forbidden status.
 *
 * @author Achour BERRAHMA <achour.berrahma at rte-france.com>
 */
@Component
public class SupervisionAccessControlFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SupervisionAccessControlFilter.class);
    private static final String SUPERVISION_SEGMENT = "supervision";
    private static final Pattern VERSION_SEGMENT_PATTERN = Pattern.compile("v\\d+");
    public static final String ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED = "{}: 403 Forbidden, Access to supervision endpoint is not allowed";

    public SupervisionAccessControlFilter(UserAdminService userAdminService) {
        super(userAdminService);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (isSupervisionEndpoint(exchange.getRequest().getPath())) {
            LOGGER.info(ACCESS_TO_SUPERVISION_ENDPOINT_IS_NOT_ALLOWED,
                    exchange.getRequest().getPath());
            return completeWithError(exchange, HttpStatus.FORBIDDEN);
        }

        return chain.filter(exchange);
    }

    /**
     * Checks whether the first path segment is {@code supervision}, or the second one is,
     * when the first segment is a version such as {@code v1}. Matrix parameters (e.g.
     * {@code ;x}) attached to a segment are ignored, exactly like Spring MVC does when
     * routing requests on the downstream services, so they can't be used to dodge this check.
     *
     * @param path the already-parsed request path (single percent-decoding pass, see class
     *             Javadoc), as given by {@link org.springframework.http.server.reactive.ServerHttpRequest#getPath()}
     */
    static boolean isSupervisionEndpoint(PathContainer path) {
        List<PathContainer.PathSegment> segments = path.elements().stream()
                .filter(PathContainer.PathSegment.class::isInstance)
                .map(PathContainer.PathSegment.class::cast)
                .toList();

        if (segments.isEmpty()) {
            return false;
        }
        if (SUPERVISION_SEGMENT.equals(segments.get(0).valueToMatch())) {
            return true;
        }
        return segments.size() > 1
                && VERSION_SEGMENT_PATTERN.matcher(segments.get(0).valueToMatch()).matches()
                && SUPERVISION_SEGMENT.equals(segments.get(1).valueToMatch());
    }

    @Override
    public int getOrder() {
        // Execute after TokenValidatorGlobalPreFilter and UserAdminControlGlobalPreFilter
        return Ordered.LOWEST_PRECEDENCE - 2;
    }
}
