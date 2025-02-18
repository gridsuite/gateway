/*
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author Thang PHAM <quyet-thang.pham at rte-france.com>
 */
@Component(value = DynamicSecurityAnalysisServer.ENDPOINT_NAME)
public class DynamicSecurityAnalysisServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "dynamic-security-analysis";

    private final ServiceURIsConfig servicesURIsConfig;

    public DynamicSecurityAnalysisServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getDynamicSecurityAnalysisServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
