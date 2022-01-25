/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import lombok.NonNull;
import org.gridsuite.gateway.ServiceURIsConfig;
import org.gridsuite.gateway.dto.AccessControlInfos;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component(value = ExploreServer.ENDPOINT_NAME)
public class ExploreServer implements EndPointElementServer {

    public static final String ENDPOINT_NAME = "explore";

    public static final String QUERY_PARAM_PARENT_DIRECTORY_ID = "parentDirectoryUuid";

    private final ServiceURIsConfig servicesURIsConfig;

    public ExploreServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public UUID getElementUuidIfExist(@NonNull RequestPath path) {
        return (path.elements().size() > 7) ? EndPointElementServer.getUuid(path.elements().get(7).value()) : null;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getExploreServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }

    @Override
    public boolean hasElementsAccessControl() {
        return true;
    }

    @Override
    public Optional<AccessControlInfos> getAccessControlInfos(@NonNull ServerHttpRequest request) {
        RequestPath path = Objects.requireNonNull(request.getPath());
        UUID elementUuid = getElementUuidIfExist(path);

        // Elements creation
        if (Objects.requireNonNull(request.getMethod()) == HttpMethod.POST) {
            if (elementUuid != null) {
                return Optional.of(AccessControlInfos.create(List.of(elementUuid)));
            } else {
                List<String> ids = request.getQueryParams().get(QUERY_PARAM_PARENT_DIRECTORY_ID);
                if (ids == null || ids.size() != 1) {
                    return Optional.empty();
                } else {
                    UUID uuid = EndPointElementServer.getUuid(ids.get(0));
                    return uuid == null ? Optional.empty() : Optional.of(AccessControlInfos.create(List.of(uuid)));
                }
            }
        } else {
            return EndPointElementServer.super.getAccessControlInfos(request);
        }
    }
}
