/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component(value = StudyServer.ENDPOINT_NAME)
public class StudyServer implements EndPointAccessControlledServer {

    public static final String ENDPOINT_NAME = "study";

    private final ServiceURIsConfig servicesURIsConfig;

    public StudyServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getStudyServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }

    @Override
    public Set<String> getUncontrolledRootPaths() {
        return Set.of("search", "svg-component-libraries", "export-network-formats", "loadflow-default-provider",
                "security-analysis-default-provider", "sensitivity-analysis-default-provider", "non-evacuated-energy-default-provider",
                "dynamic-simulation-default-provider", "optional-services", "servers");
    }
}
