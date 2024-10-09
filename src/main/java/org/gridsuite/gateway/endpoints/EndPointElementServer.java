/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import org.springframework.http.HttpMethod;

import java.util.Set;

import static org.springframework.http.HttpMethod.*;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public interface EndPointElementServer extends EndPointServer {

    String QUERY_PARAM_IDS = "ids";

    Set<HttpMethod> ALLOWED_HTTP_METHODS = Set.of(GET, HEAD,
            PUT, POST, DELETE
    );

    default Set<String> getUncontrolledRootPaths() {
        return Set.of();
    }
}
