/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "gateway")
public class ServiceURIsConfig {
    @Value("${backing-services.case.base-uri:http://case-server/}")
    String caseServerBaseUri;

    @Value("${backing-services.study-server.base-uri:http://study-server/}")
    String studyServerBaseUri;

    @Value("${backing-services.merge-orchestrator-server.base-uri:http://merge-orchestrator-server/}")
    String mergeOrchestratorServerBaseUri;

    @Value("${backing-services.notification-server.base-uri:http://notification-server/}")
    String notificationServerBaseUri;

    @Value("${backing-services.merge-notification-server.base-uri:http://merge-notification-server/}")
    String mergeNotificationServerBaseUri;

    @Value("${backing-services.actions-server.base-uri:http://actions-server/}")
    String actionsServerBaseUri;

    @Value("${backing-services.config-server.base-uri:http://config-server/}")
    String configServerBaseUri;

    @Value("${backing-services.config-notification-server.base-uri:http://config-notification-server/}")
    String configNotificationServerBaseUri;

    @Value("${backing-services.directory-server.base-uri:http://directory-server/}")
    String directoryServerBaseUri;

    @Value("${backing-services.explore-server.base-uri:http://explore-server/}")
    String exploreServerBaseUri;

    @Value("${backing-services.cgmes-boundary-server.base-uri:http://cgmes-boundary-server/}")
    String boundaryServerBaseUri;

    @Value("${backing-services.dynamic-mapping-server.base-uri:http://dynamic-mapping-server/}")
    String dynamicMappingServerBaseUri;

    @Value("${backing-services.filter-server.base-uri:http://filter-server/}")
    String filterServerBaseUri;

    @Value("${backing-services.report-server.base-uri:http://report-server/}")
    String reportServerBaseUri;

    @Value("${backing-services.directory-notification-server.base-uri:http://directory-notification-server/}")
    String directoryNotificationServerBaseUri;

    @Value("${backing-services.network-modification-server.base-uri:http://network-modification-server/}")
    String networkModificationServerBaseUri;

    @Value("${backing-services.network-conversion-server.base-uri:http://network-conversion-server/}")
    String networkConversionServerBaseUri;

    @Value("${backing-services.odre-server.base-uri:http://odre-server/}")
    String odreServerBaseUri;

    @Value("${backing-services.geo-data-server.base-uri:http://geo-data-server/}")
    String geoDataServerBaseUri;

    @Value("${backing-services.user-admin-server.base-uri:http://user-admin-server/}")
    String userAdminServerBaseUri;

    @Value("${backing-services.cgmes-gl-server.base-uri:http://cgmes-gl-server/}")
    String cgmesGlServerBaseUri;
}
