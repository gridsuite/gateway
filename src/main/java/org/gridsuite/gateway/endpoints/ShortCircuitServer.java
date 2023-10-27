/*
  Copyright (c) 2023, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@Component(value = ShortCircuitServer.ENDPOINT_NAME)
public class ShortCircuitServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "shortcircuit";

    private final ServiceURIsConfig servicesURIsConfig;

    public ShortCircuitServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getShortCircuitServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
