/*
  Copyright (c) 2020, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.gridsuite.gateway.endpoints.CgmesGlServer;
import org.gridsuite.gateway.endpoints.*;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

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

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder, ApplicationContext context) {
        return builder.routes()
            .route(p -> context.getBean(StudyServer.class).getRoute(p))
            .route(p -> context.getBean(CaseServer.class).getRoute(p))
            .route(p -> context.getBean(MergeServer.class).getRoute(p))
            .route(p -> context.getBean(StudyNotificationServer.class).getRoute(p))
            .route(p -> context.getBean(MergeNotificationServer.class).getRoute(p))
            .route(p -> context.getBean(DirectoryNotificationServer.class).getRoute(p))
            .route(p -> context.getBean(ContingencyServer.class).getRoute(p))
            .route(p -> context.getBean(ConfigServer.class).getRoute(p))
            .route(p -> context.getBean(ConfigNotificationServer.class).getRoute(p))
            .route(p -> context.getBean(DirectoryServer.class).getRoute(p))
            .route(p -> context.getBean(ExploreServer.class).getRoute(p))
            .route(p -> context.getBean(CgmesBoundaryServer.class).getRoute(p))
            .route(p -> context.getBean(DynamicMappingServer.class).getRoute(p))
            .route(p -> context.getBean(FilterServer.class).getRoute(p))
            .route(p -> context.getBean(ReportServer.class).getRoute(p))
            .route(p -> context.getBean(NetworkModificationServer.class).getRoute(p))
            .route(p -> context.getBean(NetworkConversionServer.class).getRoute(p))
            .route(p -> context.getBean(OdreServer.class).getRoute(p))
            .route(p -> context.getBean(GeoDataServer.class).getRoute(p))
                .route(p -> context.getBean(CgmesGlServer.class).getRoute(p))
            .build();
    }
}
