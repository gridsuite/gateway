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
 * @author Ayoub LABIDI <ayoub.labidi at rte-france.com>
 */
@RequiredArgsConstructor
@Component(value = SpreadsheetConfigCollection.ENDPOINT_NAME)
public class SpreadsheetConfigCollection implements EndPointServer {

    public static final String ENDPOINT_NAME = "spreadsheet-config-collections";

    private final ServiceURIsConfig servicesURIsConfig;

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getSpreadsheetConfigServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
