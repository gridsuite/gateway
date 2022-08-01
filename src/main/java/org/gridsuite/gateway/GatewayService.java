/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import org.gridsuite.gateway.dto.OpenIdConfiguration;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Service
public class GatewayService {
    private WebClient.Builder webClientBuilder;

    public GatewayService() {
        webClientBuilder = WebClient.builder();
    }

    public Mono<String> getJwksUrl(String issBaseUri) {
        WebClient webClient = webClientBuilder.uriBuilderFactory(new DefaultUriBuilderFactory(issBaseUri)).build();

        String path = UriComponentsBuilder.fromPath("/.well-known/openid-configuration")
            .toUriString();

        return webClient.get()
                 .uri(path)
                 .retrieve()
                 .bodyToMono(OpenIdConfiguration.class)
                 .single()
                 .map(OpenIdConfiguration::getJwksUri);
    }
}
