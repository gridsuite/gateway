/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.endpoints;

import lombok.NonNull;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
public interface EndPointElementServer extends EndPointServer {

    String QUERY_PARAM_ID = "id";

    Set<HttpMethod> ALLOWED_HTTP_METHODS = Set.of(HttpMethod.GET, HttpMethod.HEAD,
        HttpMethod.PUT, HttpMethod.POST, HttpMethod.DELETE
    );

    private static UUID getUuid(String uuid) {
        try {
            return UUID.fromString(uuid);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static UUID getElementUuidIfExist(@NonNull RequestPath path) {
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

    default List<UUID> getElementsUuids(@NonNull ServerHttpRequest request) {
        RequestPath path = Objects.requireNonNull(request.getPath());
        UUID elementUuid = EndPointElementServer.getElementUuidIfExist(path);

        // /<elements>/{studyUuid} or /<elements>/**?id=
        switch (Objects.requireNonNull(request.getMethod())) {
            case GET: {
                if (elementUuid != null) {
                    return List.of(elementUuid);
                } else {
                    if (request.getQueryParams().get(QUERY_PARAM_ID) == null) {
                        return List.of();
                    } else {
                        return request.getQueryParams().get(QUERY_PARAM_ID).stream().map(UUID::fromString).collect(Collectors.toList());
                    }
                }
            }
            case POST:
            case PUT:
            case DELETE:
                return elementUuid == null ? List.of() : List.of(elementUuid);
            default:
                return List.of();
        }
    }
}
