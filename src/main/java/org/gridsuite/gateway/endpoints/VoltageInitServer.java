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
 * @author Hugo Marcellin <hugo.marcelin at rte-france.com>
 */
@Component(value = VoltageInitServer.ENDPOINT_NAME)
public class VoltageInitServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "voltage-init";

    private final ServiceURIsConfig servicesURIsConfig;

    public VoltageInitServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getVoltageInitServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
