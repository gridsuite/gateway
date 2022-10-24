/*
  Copyright (c) 2022, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Component(value = SensitivityAnalysisServer.ENDPOINT_NAME)
public class SensitivityAnalysisServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "sensitivity-analysis";

    private final ServiceURIsConfig servicesURIsConfig;

    public SensitivityAnalysisServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getSensitivityAnalysisServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }

    @Override
    public Set<String> getUncontrolledRootPaths() {
        return Set.of("results-threshold-default-value");
    }
}
