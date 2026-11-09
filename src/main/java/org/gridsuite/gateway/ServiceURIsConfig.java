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
    @Value("${gridsuite.services.study-server.base-uri:http://study-server/}")
    String studyServerBaseUri;

    @Value("${gridsuite.services.study-notification-server.base-uri:http://study-notification-server/}")
    String studyNotificationServerBaseUri;

    @Value("${gridsuite.services.config-server.base-uri:http://config-server/}")
    String configServerBaseUri;

    @Value("${gridsuite.services.config-notification-server.base-uri:http://config-notification-server/}")
    String configNotificationServerBaseUri;

    @Value("${gridsuite.services.explore-server.base-uri:http://explore-server/}")
    String exploreServerBaseUri;

    @Value("${gridsuite.services.dynamic-mapping-server.base-uri:http://dynamic-mapping-server/}")
    String dynamicMappingServerBaseUri;

    @Value("${gridsuite.services.directory-notification-server.base-uri:http://directory-notification-server/}")
    String directoryNotificationServerBaseUri;

    @Value("${gridsuite.services.user-admin-server.base-uri:http://user-admin-server/}")
    String userAdminServerBaseUri;

    @Value("${gridsuite.services.case-import-server.base-uri:http://case-import-server/}")
    String caseImportServerBaseUri;

    @Value("${gridsuite.services.user-identity-server.base-uri:http://user-identity-server/}")
    String userIdentityServerBaseUri;

    @Value("${gridsuite.services.monitor-server.base-uri:http://monitor-server/}")
    String monitorServerBaseUri;

    @Value("${gridsuite.services.monitor-notification-server.base-uri:http://monitor-notification-server/}")
    String monitorNotificationServerBaseUri;
}
