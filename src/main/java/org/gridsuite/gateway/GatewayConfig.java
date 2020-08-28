/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
@EnableConfigurationProperties(UriConfiguration.class)
public class GatewayConfig {
    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder, UriConfiguration uriConfiguration) {
        return builder.routes()
            .route(p -> p
                    .path("/study/**")
                    .filters(f -> f.rewritePath("/study/(.*)", "/$1"))
                    .uri(uriConfiguration.getStudyServerBaseUri())
            )
            .route(p -> p
                    .path("/case/**")
                    .filters(f -> f.rewritePath("/case/(.*)", "/$1"))
                    .uri(uriConfiguration.getCaseServerBaseUri())
            )
            .route(p -> p
                    .path("/notification/**")
                    .filters(f -> f.rewritePath("/notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getNotificationServerBaseUri())
            )
            .route(p -> p
                    .path("/merge-notification/**")
                    .filters(f -> f.rewritePath("/merge-notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getNotificationServerBaseUri())
            )
            .build();
    }
}

@ConfigurationProperties
class UriConfiguration {
    @Value("${backing-services.case.base-uri:http://case-server/}") String caseServerBaseUri;
    @Value("${backing-services.study-server.base-uri:http://study-server/}") String studyServerBaseUri;
    @Value("${backing-services.notification-server.base-uri:http://notification-server/}") String notificationServerBaseUri;
    @Value("${backing-services.merge-notification-server.base-uri:http://merge-notification-server/}") String mergeNotificationServerBaseUri;

    public String getCaseServerBaseUri() {
        return caseServerBaseUri;
    }

    public void setCaseServerBaseUri(String caseServerBaseUri) {
        this.caseServerBaseUri = caseServerBaseUri;
    }

    public String getStudyServerBaseUri() {
        return studyServerBaseUri;
    }

    public void setStudyServerBaseUri(String studyServerBaseUri) {
        this.studyServerBaseUri = studyServerBaseUri;
    }

    public String getNotificationServerBaseUri() {
        return notificationServerBaseUri;
    }

    public void setNotificationServerBaseUri(String notificationServerBaseUri) {
        this.notificationServerBaseUri = notificationServerBaseUri;
    }

    public String getMergeNotificationServerBaseUri() {
        return mergeNotificationServerBaseUri;
    }

    public void setMergeNotificationServerBaseUri(String mergeNotificationServerBaseUri) {
        this.mergeNotificationServerBaseUri = mergeNotificationServerBaseUri;
    }
}
