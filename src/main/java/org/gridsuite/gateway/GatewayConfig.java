/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import java.net.*;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.validators.*;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@EnableHystrix
@Configuration
public class GatewayConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(GatewayConfig.class);

    @Value("${backing-services.case.base-uri:http://case-server/}") String caseServerBaseUri;
    @Value("${backing-services.study-server.base-uri:http://study-server/}") String studyServerBaseUri;
    @Value("${jwk-url}")  String jwkUri;
    @Value("${client-id}")  String clientID;

    public String getClientID() {
        return clientID;
    }

    @Component
    public class TokenValidatorGlobalPreFilter implements GlobalFilter {
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            LOGGER.debug("checking authorization");
            List<String> ls = exchange.getRequest().getHeaders().get("Authorization");
            assert ls != null;
            String authorization = ls.get(0);
            String token = authorization.split(" ")[1];
            DecodedJWT jwt = com.auth0.jwt.JWT.decode(token);

            try {
                JWT idToken = JWTParser.parse(token);
                // The required parameters
                Issuer iss = new Issuer(jwt.getIssuer());
                ClientID clientID = new ClientID(getClientID());
                JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
                URL jwkSetURL = null;
                try {
                    jwkSetURL = new URL(jwkUri);
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }

                // Create validator for signed ID tokens
                IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

                IDTokenClaimsSet claims  = validator.validate(idToken, null);
                // we can safely trust the JWT
                LOGGER.debug("The token is valid");
            } catch (Exception e) {
                LOGGER.debug("The token cannot be trusted");
                throw new IllegalArgumentException("The token cannot be trusted" + e.getMessage());
            }
            return chain.filter(exchange);
        }
    }

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            .route(p -> p
                    .path("/study/**")
                    .filters(f -> f.rewritePath("/study/(.*)", "/$1"))
                    .uri(studyServerBaseUri)
            )
            .route(p -> p
                    .path("/case/**")
                    .filters(f -> f.hystrix(config -> config.setName("study").setFallbackUri("forward:/caseFallback"))
                            .rewritePath("/case/(.*)", "/$1"))
                    .uri(caseServerBaseUri)
            )
            .build();
    }
}
