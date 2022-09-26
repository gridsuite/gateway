/*
  Copyright (c) 2022, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author bendaamerahm <ahmed.bendaamer at rte-france.com>
 */
@Component(value = CgmesGlServer.ENDPOINT_NAME)
public class CgmesGlServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "cgmes-gl";

    private final ServiceURIsConfig servicesURIsConfig;

    public CgmesGlServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getCgmesGlServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
