/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.services;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.jwt.JWTClaimsSet;

import reactor.core.publisher.Mono;

/**
 * @author Jon Schuhmacher <jon.harper at rte-france.com>
 */
@Service
public class UserIdentityService {

    private static final String USER_IDENTITY_SERVER_API_VERSION = "v1";

    private static final String DELIMITER = "/";

    private static final String USER_IDENTITY_SERVER_STORE_PATH = DELIMITER + USER_IDENTITY_SERVER_API_VERSION + DELIMITER
            + "users/identities/";

    private final WebClient webClient;

    @Autowired
    public UserIdentityService(ServiceURIsConfig servicesURIsConfig, WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl(servicesURIsConfig.getUserIdentityServerBaseUri()).build();
    }

    // NOTE: this API actually responds with the parsed identity but we don't use it here
    public Mono<Void> storeToken(String sub, JWTClaimsSet jwtClaimsSet) {
        return webClient.put()
                .uri(uriBuilder -> uriBuilder
                        .path(USER_IDENTITY_SERVER_STORE_PATH + DELIMITER + sub)
                        .build()
                ).bodyValue(jwtClaimsSet.getClaims()).retrieve().bodyToMono(Void.class);
    }

}
