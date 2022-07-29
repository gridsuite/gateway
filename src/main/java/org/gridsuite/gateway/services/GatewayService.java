/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway.services;

import org.gridsuite.gateway.dto.OpenIdConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Objects;

@Service
public class GatewayService {
    public static final String CACHE_NAME = "JwksUrl";
    public static final String CACHE_KEY = "#issBaseUri";
    private RestTemplate issRest;

    public GatewayService() {
        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();
        issRest = restTemplateBuilder.build();
    }

    @Cacheable(cacheNames = {CACHE_NAME}, key = CACHE_KEY)
    public String getJwksUrl(String issBaseUri) {
        issRest.setUriTemplateHandler(new DefaultUriBuilderFactory(issBaseUri));

        String path = UriComponentsBuilder.fromPath("/.well-known/openid-configuration")
            .toUriString();

        ResponseEntity<OpenIdConfiguration> responseEntity = issRest.exchange(path,
            HttpMethod.GET,
            HttpEntity.EMPTY,
            OpenIdConfiguration.class);

        return Objects.requireNonNull(responseEntity.getBody()).getJwksUri();
    }
}
