/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Configuration
@PropertySource(value = {"classpath:allowed-issuers.yml"})
@PropertySource(value = {"file:/config/allowed-issuers.yml"}, ignoreResourceNotFound = true)
public class GatewayConfig {

    static final String HEADER_USER_ID = "userId";

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder, ServicesURIsConfig servicesURIsConfig) {
        return builder.routes()
            .route(p -> p
                .path("/study/**")
                .filters(f -> f.rewritePath("/study/(.*)", "/$1"))
                .uri(servicesURIsConfig.getStudyServerBaseUri())
            )
            .route(p -> p
                .path("/case/**")
                .filters(f -> f.rewritePath("/case/(.*)", "/$1"))
                .uri(servicesURIsConfig.getCaseServerBaseUri())
            )
            .route(p -> p
                .path("/merge/**")
                .filters(f -> f.rewritePath("/merge/(.*)", "/$1"))
                .uri(servicesURIsConfig.getMergeOrchestratorServerBaseUri())
            )
            .route(p -> p
                .path("/notification/**")
                .filters(f -> f.rewritePath("/notification/(.*)", "/$1"))
                .uri(servicesURIsConfig.getNotificationServerBaseUri())
            )
            .route(p -> p
                .path("/merge-notification/**")
                .filters(f -> f.rewritePath("/merge-notification/(.*)", "/$1"))
                .uri(servicesURIsConfig.getMergeNotificationServerBaseUri())
            )
            .route(p -> p
                .path("/directory-notification/**")
                .filters(f -> f.rewritePath("/directory-notification/(.*)", "/$1"))
                .uri(servicesURIsConfig.getDirectoryNotificationServerBaseUri())
            )
            .route(p -> p
                .path("/actions/**")
                .filters(f -> f.rewritePath("/actions/(.*)", "/$1"))
                .uri(servicesURIsConfig.getActionsServerBaseUri())
            )
            .route(p -> p
                .path("/config/**")
                .filters(f -> f.rewritePath("/config/(.*)", "/$1"))
                .uri(servicesURIsConfig.getConfigServerBaseUri())
            )
            .route(p -> p
                .path("/config-notification/**")
                .filters(f -> f.rewritePath("/config-notification/(.*)", "/$1"))
                .uri(servicesURIsConfig.getConfigNotificationServerBaseUri())
            )
            .route(p -> p
                .path("/directory/**")
                .filters(f -> f.rewritePath("/directory/(.*)", "/$1"))
                .uri(servicesURIsConfig.getDirectoryServerBaseUri())
            )
            .route(p -> p
                .path("/explore/**")
                .filters(f -> f.rewritePath("/explore/(.*)", "/$1"))
                .uri(servicesURIsConfig.getExploreServerBaseUri())
            )
            .route(p -> p
                .path("/boundary/**")
                .filters(f -> f.rewritePath("/boundary/(.*)", "/$1"))
                .uri(servicesURIsConfig.getBoundaryServerBaseUri())
            )
            .route(p -> p
                .path("/dynamic-mapping/**")
                .filters(f -> f.rewritePath("/dynamic-mapping/(.*)", "/$1"))
                .uri(servicesURIsConfig.getDynamicMappingServerBaseUri())
            )
            .route(p -> p
                .path("/filter/**")
                .filters(f -> f.rewritePath("/filter/(.*)", "/$1"))
                .uri(servicesURIsConfig.getFilterServerBaseUri())
            )
            .route(p -> p
                .path("/report/**")
                .filters(f -> f.rewritePath("/report/(.*)", "/$1"))
                .uri(servicesURIsConfig.getReportServerBaseUri())
            )
            .build();
    }
}
