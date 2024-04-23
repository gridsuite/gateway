/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import lombok.NonNull;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.builder.Buildable;
import org.springframework.cloud.gateway.route.builder.PredicateSpec;

import static org.gridsuite.gateway.GatewayConfig.END_POINT_SERVICE_NAME;

/**
 * Declare a service/server accessible on this gateway under path {@code <host_gateway>/<service_name>/*}
 * and redirect it to {@code <host_service>/*}.
 *
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public interface EndPointServer {
    String getEndpointBaseUri();

    String getEndpointName();

    default Buildable<Route> getRoute(@NonNull PredicateSpec p) {
        return p.path(String.format("/%s/**", getEndpointName()))
            .filters(f -> f.rewritePath(String.format("/%s/(.*)", getEndpointName()), "/$1"))
            .metadata(END_POINT_SERVICE_NAME, getEndpointName())
            .uri(getEndpointBaseUri());
    }
}
