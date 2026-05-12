/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;


/**
 * @author Kevin Le Saulnier <kevin.le-saulnier at rte-france.com>
 */
@Component(value = MonitorServer.ENDPOINT_NAME)
public class MonitorServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "monitor";

    private final ServiceURIsConfig servicesURIsConfig;

    public MonitorServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getMonitorServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
