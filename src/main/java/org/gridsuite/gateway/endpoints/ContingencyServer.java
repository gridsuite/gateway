/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component(value = ContingencyServer.ENDPOINT_NAME)
public class ContingencyServer implements EndPointElementServer {

    public static final String ENDPOINT_NAME = "actions";

    private final ServiceURIsConfig servicesURIsConfig;

    public ContingencyServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getActionsServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
