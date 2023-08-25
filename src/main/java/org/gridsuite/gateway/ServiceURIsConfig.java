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
    @Value("${powsybl.services.case-server.base-uri:http://case-server/}")
    String caseServerBaseUri;

    @Value("${gridsuite.services.study-server.base-uri:http://study-server/}")
    String studyServerBaseUri;

    @Value("${gridsuite.services.merge-orchestrator-server.base-uri:http://merge-orchestrator-server/}")
    String mergeOrchestratorServerBaseUri;

    @Value("${gridsuite.services.study-notification-server.base-uri:http://study-notification-server/}")
    String studyNotificationServerBaseUri;

    @Value("${gridsuite.services.merge-notification-server.base-uri:http://merge-notification-server/}")
    String mergeNotificationServerBaseUri;

    @Value("${gridsuite.services.actions-server.base-uri:http://actions-server/}")
    String actionsServerBaseUri;

    @Value("${gridsuite.services.config-server.base-uri:http://config-server/}")
    String configServerBaseUri;

    @Value("${gridsuite.services.config-notification-server.base-uri:http://config-notification-server/}")
    String configNotificationServerBaseUri;

    @Value("${gridsuite.services.directory-server.base-uri:http://directory-server/}")
    String directoryServerBaseUri;

    @Value("${gridsuite.services.explore-server.base-uri:http://explore-server/}")
    String exploreServerBaseUri;

    @Value("${gridsuite.services.cgmes-boundary-server.base-uri:http://cgmes-boundary-server/}")
    String boundaryServerBaseUri;

    @Value("${gridsuite.services.dynamic-mapping-server.base-uri:http://dynamic-mapping-server/}")
    String dynamicMappingServerBaseUri;

    @Value("${gridsuite.services.filter-server.base-uri:http://filter-server/}")
    String filterServerBaseUri;

    @Value("${gridsuite.services.report-server.base-uri:http://report-server/}")
    String reportServerBaseUri;

    @Value("${gridsuite.services.directory-notification-server.base-uri:http://directory-notification-server/}")
    String directoryNotificationServerBaseUri;

    @Value("${gridsuite.services.network-modification-server.base-uri:http://network-modification-server/}")
    String networkModificationServerBaseUri;

    @Value("${powsybl.services.network-conversion-server.base-uri:http://network-conversion-server/}")
    String networkConversionServerBaseUri;

    @Value("${gridsuite.services.odre-server.base-uri:http://odre-server/}")
    String odreServerBaseUri;

    @Value("${gridsuite.services.geo-data-server.base-uri:http://geo-data-server/}")
    String geoDataServerBaseUri;

    @Value("${gridsuite.services.user-admin-server.base-uri:http://user-admin-server/}")
    String userAdminServerBaseUri;

    @Value("${gridsuite.services.cgmes-gl-server.base-uri:http://cgmes-gl-server/}")
    String cgmesGlServerBaseUri;

    @Value("${gridsuite.services.sensitivity-analysis-server.base-uri:http://sensitivity-analysis-server/}")
    String sensitivityAnalysisServerBaseUri;

    @Value("${gridsuite.services.loadflow-server.base-uri:http://loadflow-server/}")
    String loadFlowServerBaseUri;

    @Value("${gridsuite.services.security-analysis-server.base-uri:http://security-analysis-server/}")
    String securityAnalysisServerBaseUri;

    @Value("${gridsuite.services.dynamic-simulation-server.base-uri:http://dynamic-simulation-server/}")
    String dynamicSimulationServerBaseUri;

    @Value("${gridsuite.services.case-import-server.base-uri:http://case-import-server/}")
    String caseImportServerBaseUri;
}
