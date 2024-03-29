/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import lombok.NonNull;
import org.gridsuite.gateway.dto.AccessControlInfos;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpMethod.*;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public interface EndPointElementServer extends EndPointServer {

    String QUERY_PARAM_IDS = "ids";

    Set<HttpMethod> ALLOWED_HTTP_METHODS = Set.of(GET, HEAD,
            PUT, POST, DELETE
    );

    static UUID getUuid(String uuid) {
        try {
            return UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    default UUID getElementUuidIfExist(@NonNull RequestPath path) {
        return (path.elements().size() > 5) ? getUuid(path.elements().get(5).value()) : null;
    }

    default boolean isAllowedMethod(HttpMethod httpMethod) {
        return ALLOWED_HTTP_METHODS.contains(httpMethod);
    }

    default Set<String> getUncontrolledRootPaths() {
        return Set.of();
    }

    default boolean isNotControlledRootPath(String rootPath) {
        return getUncontrolledRootPaths().contains(rootPath);
    }

    @Override
    default boolean hasElementsAccessControl() {
        return true;
    }

    default Optional<AccessControlInfos> getAccessControlInfos(@NonNull ServerHttpRequest request) {
        RequestPath path = Objects.requireNonNull(request.getPath());
        UUID elementUuid = getElementUuidIfExist(path);

        // /<elements>/{elementUuid} or /<elements>/**?id=
        HttpMethod httpMethod = Objects.requireNonNull(request.getMethod());
        if (httpMethod.equals(HEAD) || httpMethod.equals(GET)) {
            if (elementUuid != null) {
                return Optional.of(AccessControlInfos.create(List.of(elementUuid)));
            } else {
                if (request.getQueryParams().get(QUERY_PARAM_IDS) == null) {
                    return Optional.empty();
                } else {
                    List<String> ids = request.getQueryParams().get(QUERY_PARAM_IDS);
                    List<UUID> elementUuids = ids.stream().map(EndPointElementServer::getUuid).filter(Objects::nonNull).collect(Collectors.toList());
                    return elementUuids.size() == ids.size() ? Optional.of(AccessControlInfos.create(elementUuids)) : Optional.empty();
                }
            }
        } else if (httpMethod.equals(POST) || httpMethod.equals(PUT) || httpMethod.equals(DELETE)) {
            return elementUuid == null ? Optional.empty() : Optional.of(AccessControlInfos.create(List.of(elementUuid)));
        }
        return Optional.empty();
    }
}
