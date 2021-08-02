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
                    .path("/merge/**")
                    .filters(f -> f.rewritePath("/merge/(.*)", "/$1"))
                    .uri(uriConfiguration.getMergeOrchestratorServerBaseUri())
            )
            .route(p -> p
                    .path("/notification/**")
                    .filters(f -> f.rewritePath("/notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getNotificationServerBaseUri())
            )
            .route(p -> p
                    .path("/merge-notification/**")
                    .filters(f -> f.rewritePath("/merge-notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getMergeNotificationServerBaseUri())
            )
            .route(p -> p
                    .path("/directory-notification/**")
                    .filters(f -> f.rewritePath("/directory-notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getDirectoryNotificationServerBaseUri())
            )
            .route(p -> p
                    .path("/actions/**")
                    .filters(f -> f.rewritePath("/actions/(.*)", "/$1"))
                    .uri(uriConfiguration.getActionsServerBaseUri())
            )
            .route(p -> p
                    .path("/config/**")
                    .filters(f -> f.rewritePath("/config/(.*)", "/$1"))
                    .uri(uriConfiguration.getConfigServerBaseUri())
            )
            .route(p -> p
                    .path("/config-notification/**")
                    .filters(f -> f.rewritePath("/config-notification/(.*)", "/$1"))
                    .uri(uriConfiguration.getConfigNotificationServerBaseUri())
            )
            .route(p -> p
                    .path("/directory/**")
                    .filters(f -> f.rewritePath("/directory/(.*)", "/$1"))
                    .uri(uriConfiguration.getDirectoryServerBaseUri())
            )
            .route(p -> p
                .path("/boundary/**")
                .filters(f -> f.rewritePath("/boundary/(.*)", "/$1"))
                .uri(uriConfiguration.getBoundaryServerBaseUri())
            )
            .route(p -> p
                .path("/dynamic-mapping/**")
                .filters(f -> f.rewritePath("/dynamic-mapping/(.*)", "/$1"))
                .uri(uriConfiguration.getDynamicMappingServerBaseUri())
            )
            .route(p -> p
                    .path("/filter/**")
                    .filters(f -> f.rewritePath("/filter/(.*)", "/$1"))
                    .uri(uriConfiguration.getFilterServerBaseUri())
            )
            .route(p -> p
                    .path("/report/**")
                    .filters(f -> f.rewritePath("/report/(.*)", "/$1"))
                    .uri(uriConfiguration.getReportServerBaseUri())
            )
            .build();
    }
}

@ConfigurationProperties
class UriConfiguration {
    @Value("${backing-services.case.base-uri:http://case-server/}") String caseServerBaseUri;
    @Value("${backing-services.study-server.base-uri:http://study-server/}") String studyServerBaseUri;
    @Value("${backing-services.merge-orchestrator-server.base-uri:http://study-server/}") String mergeOrchestratorServerBaseUri;
    @Value("${backing-services.notification-server.base-uri:http://notification-server/}") String notificationServerBaseUri;
    @Value("${backing-services.merge-notification-server.base-uri:http://merge-notification-server/}") String mergeNotificationServerBaseUri;
    @Value("${backing-services.actions-server.base-uri:http://actions-server/}") String actionsServerBaseUri;
    @Value("${backing-services.config-server.base-uri:http://config-server/}") String configServerBaseUri;
    @Value("${backing-services.config-notification-server.base-uri:http://config-notification-server/}") String configNotificationServerBaseUri;
    @Value("${backing-services.directory-server.base-uri:http://directory-server/}") String directoryServerBaseUri;
    @Value("${backing-services.cgmes-boundary-server.base-uri:http://cgmes-boundary-server/}") String boundaryServerBaseUri;
    @Value("${backing-services.dynamic-mapping-server.base-uri:http://dynamic-mapping-server/}") String dynamicMappingServerBaseUri;
    @Value("${backing-services.filter-server.base-uri:http://filter-server/}") String filterServerBaseUri;
    @Value("${backing-services.report-server.base-uri:http://report-server/}") String reportServerBaseUri;
    @Value("${backing-services.directory-notification-server.base-uri:http://directory-notification-server/}") String directoryNotificationServerBaseUri;

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

    public String getMergeOrchestratorServerBaseUri() {
        return mergeOrchestratorServerBaseUri;
    }

    public void setMergeOrchestratorServerBaseUri(String mergeOrchestratorServerBaseUri) {
        this.mergeOrchestratorServerBaseUri = mergeOrchestratorServerBaseUri;
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

    public String getDirectoryNotificationServerBaseUri() {
        return directoryNotificationServerBaseUri;
    }

    public void setDirectoryNotificationServerBaseUri(String directoryNotificationServerBaseUri) {
        this.directoryNotificationServerBaseUri = directoryNotificationServerBaseUri;
    }

    public String getActionsServerBaseUri() {
        return actionsServerBaseUri;
    }

    public void setActionsServerBaseUri(String actionsServerBaseUri) {
        this.actionsServerBaseUri = actionsServerBaseUri;
    }

    public String getConfigServerBaseUri() {
        return configServerBaseUri;
    }

    public void setConfigServerBaseUri(String configServerBaseUri) {
        this.configServerBaseUri = configServerBaseUri;
    }

    public String getConfigNotificationServerBaseUri() {
        return configNotificationServerBaseUri;
    }

    public void setConfigNotificationServerBaseUri(String configNotificationServerBaseUri) {
        this.configNotificationServerBaseUri = configNotificationServerBaseUri;
    }

    public String getDirectoryServerBaseUri() {
        return directoryServerBaseUri;
    }

    public void setDirectoryServerBaseUri(String directoryServerBaseUri) {
        this.directoryServerBaseUri = directoryServerBaseUri;
    }

    public String getBoundaryServerBaseUri() {
        return boundaryServerBaseUri;
    }

    public void setBoundaryServerBaseUri(String boundaryServerBaseUri) {
        this.boundaryServerBaseUri = boundaryServerBaseUri;
    }

    public String getDynamicMappingServerBaseUri() {
        return dynamicMappingServerBaseUri;
    }

    public void setDynamicMappingServerBaseUri(String dynamicMappingServerBaseUri) {
        this.dynamicMappingServerBaseUri = dynamicMappingServerBaseUri;
    }

    public String getFilterServerBaseUri() {
        return filterServerBaseUri;
    }

    public void setFilterServerBaseUri(String filterServerBaseUri) {
        this.filterServerBaseUri = filterServerBaseUri;
    }

    public String getReportServerBaseUri() {
        return reportServerBaseUri;
    }

    public void setReportServerBaseUri(String reportServerBaseUri) {
        this.reportServerBaseUri = reportServerBaseUri;
    }
}
