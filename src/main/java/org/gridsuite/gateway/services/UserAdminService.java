/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.services;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * @author Etienne Homer <etienne.homer at rte-france.com>
 */
@Service
public class UserAdminService {

    private static final String USER_ADMIN_SERVER_API_VERSION = "v1";

    private static final String DELIMITER = "/";

    private static final String USER_ADMIN_SERVER_ROOT_PATH = DELIMITER + USER_ADMIN_SERVER_API_VERSION + DELIMITER + "users";

    private static final String USER_ADMIN_RECORD_USER_CONNECTION_URL = USER_ADMIN_SERVER_ROOT_PATH + DELIMITER + "{sub}/record-connection";

    private final WebClient webClient;

    public UserAdminService(ServiceURIsConfig servicesURIsConfig, WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl(servicesURIsConfig.getUserAdminServerBaseUri()).build();
    }

    public Mono<Void> userRecordConnection(String sub, boolean isConnectionAccepted) {
        return webClient
                .head()
                .uri(uriBuilder -> uriBuilder
                        .path(USER_ADMIN_RECORD_USER_CONNECTION_URL)
                        .queryParam("isConnectionAccepted", isConnectionAccepted)
                        .build(sub)  // Replace {sub} in the path with the actual value
                )
                .retrieve()
                .bodyToMono(Void.class);
    }
}
