/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import lombok.RequiredArgsConstructor;
import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

/**
 * @author David BRAQUART <david.braquart at rte-france.com>
 */
@RequiredArgsConstructor
@Component(value = StudyConfigServer.ENDPOINT_NAME)
public class StudyConfigServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "study-config";

    private final ServiceURIsConfig servicesURIsConfig;

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getStudyConfigServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
