/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.config.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component(value = DirectoryNotificationServer.ENDPOINT_NAME)
public class DirectoryNotificationServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "directory-notification";

    private final ServiceURIsConfig servicesURIsConfig;

    public DirectoryNotificationServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getDirectoryNotificationServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
