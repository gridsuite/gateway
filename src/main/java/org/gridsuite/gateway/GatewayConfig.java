/*
  Copyright (c) 2020, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.gridsuite.gateway.endpoints.EndPointServer;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.List;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Configuration
@PropertySource(value = {"classpath:allowed-issuers.yml"})
@PropertySource(value = {"file:/config/allowed-issuers.yml"}, ignoreResourceNotFound = true)
public class GatewayConfig {

    public static final String END_POINT_SERVICE_NAME = "end_point_service_name";

    public static final String HEADER_USER_ID = "userId";
    public static final String HEADER_CLIENT_ID = "clientId";

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder, List<EndPointServer> servers) {
        final RouteLocatorBuilder.Builder routes = builder.routes();
        for (final EndPointServer server : servers) {
            routes.route(server.getClass().getName(), server::getRoute);
        }
        return routes.build();
    }
}
