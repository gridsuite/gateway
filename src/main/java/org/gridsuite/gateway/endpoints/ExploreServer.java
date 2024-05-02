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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@Component(value = ExploreServer.ENDPOINT_NAME)
public class ExploreServer implements EndPointElementServer {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExploreServer.class);

    public static final String ENDPOINT_NAME = "explore";

    public static final String QUERY_PARAM_PARENT_DIRECTORY_ID = "parentDirectoryUuid";
    public static final String QUERY_PARAM_DUPLICATE_FROM_ID = "duplicateFrom";

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

    private UUID getUniqueOptionalUuidFromParam(@NonNull ServerHttpRequest request, @NonNull String queryParamName) {
        List<String> ids = request.getQueryParams().get(queryParamName);
        if (ids != null && ids.size() != 1) {
            throw new IllegalArgumentException("There must be only one " + queryParamName);
        }
        if (ids != null) {
            UUID uuid = EndPointElementServer.getUuid(ids.get(0));
            if (uuid == null) {
                throw new IllegalArgumentException(queryParamName + " must be an UUID");
            }
            return uuid;
        }
        return null;
    }

    @Override
    public Optional<AccessControlInfos> getAccessControlInfos(@NonNull ServerHttpRequest request) {
        RequestPath path = Objects.requireNonNull(request.getPath());
        UUID elementUuid = getElementUuidIfExist(path);
        if (Objects.requireNonNull(request.getMethod()) != HttpMethod.POST) {
            return EndPointElementServer.super.getAccessControlInfos(request);
        }
        // Elements creation
        if (elementUuid != null) {
            return Optional.of(AccessControlInfos.create(List.of(elementUuid)));
        }
        try {
            List<UUID> uuidsToControl = new ArrayList<>();
            UUID duplicateFromUuid = getUniqueOptionalUuidFromParam(request, QUERY_PARAM_DUPLICATE_FROM_ID);
            if (duplicateFromUuid != null) {
                uuidsToControl.add(duplicateFromUuid);
            }
            UUID parentDirectoryUuid = getUniqueOptionalUuidFromParam(request, QUERY_PARAM_PARENT_DIRECTORY_ID);
            if (parentDirectoryUuid != null) {
                uuidsToControl.add(parentDirectoryUuid);
            }
            if (uuidsToControl.isEmpty()) {
                // At least one of the param is required
                return Optional.empty();
            }
            // Check resources access
            return Optional.of(AccessControlInfos.create(uuidsToControl));
        } catch (IllegalArgumentException e) {
            LOGGER.error(e.getMessage());
            return Optional.empty();
        }
    }
}
