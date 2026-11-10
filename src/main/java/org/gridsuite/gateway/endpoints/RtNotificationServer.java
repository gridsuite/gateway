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
 * @author Mohamed Ben Rejeb <mohamed.benrejeb at rte-france.com>
 */
@Component(value = RtNotificationServer.ENDPOINT_NAME)
public class RtNotificationServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "rt-notification";

    private final ServiceURIsConfig servicesURIsConfig;

    public RtNotificationServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getRtNotificationServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
