/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import java.net.*;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.validators.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Configuration
@EnableConfigurationProperties(UriConfiguration.class)
public class GatewayConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(GatewayConfig.class);

    private final GatewayService gatewayService;

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    public GatewayConfig(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
    }

    @Component
    @Profile({ "production" })
    public class TokenValidatorGlobalPreFilter implements GlobalFilter {
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            LOGGER.debug("checking authorization");
            List<String> ls = exchange.getRequest().getHeaders().get("Authorization");
            if (ls == null) {
                throw new GatewayException("Authorization header is required");
            }

            LOGGER.debug("checking issuer");
            String authorization = ls.get(0);
            String token = authorization.split(" ")[1];
            JWT jwt;
            JWTClaimsSet jwtClaimsSet;
            try {
                jwt = JWTParser.parse(token);
                jwtClaimsSet = jwt.getJWTClaimsSet();
            } catch (java.text.ParseException e) {
                // Invalid plain JOSE object encoding
                throw new GatewayException("Invalid plain JOSE object encoding");
            }

            if (allowedIssuers.stream().noneMatch(iss -> iss.startsWith(jwtClaimsSet.getIssuer()))) {
                throw new GatewayException(jwtClaimsSet.getIssuer() + " Issuer is not in the issuers white list");
            }

            try {
                JWT idToken = JWTParser.parse(token);
                Issuer iss = new Issuer(jwt.getJWTClaimsSet().getIssuer());
                ClientID clientID = new ClientID(jwt.getJWTClaimsSet().getAudience().get(0));

                JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());
                URL jwkSetURL = null;
                try {
                    jwkSetURL = new URL(gatewayService.getJwksUrl(jwt.getJWTClaimsSet().getIssuer()));
                } catch (MalformedURLException e) {
                    throw new GatewayException("MalformedURLException : " + e.getMessage());
                }

                // Create validator for signed ID tokens
                IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

                IDTokenClaimsSet claims  = validator.validate(idToken, null);
                // we can safely trust the JWT
                LOGGER.debug("Token verified, it can be trusted");
            } catch (Exception e) {
                LOGGER.debug("The token cannot be trusted");
                throw new GatewayException("The token cannot be trusted : " + e.getMessage());
            }
            return chain.filter(exchange);
        }
    }

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder, UriConfiguration uriConfiguration) {
        return builder.routes()
            .route(p -> p
                    .path("/study/**")
                    .filters(f -> f.rewritePath("/study/(.*)", "/$1"))
                    .uri(uriConfiguration.getStudyServerBaseUri())
            )
            .route(p -> p
                    .path("/case/**")
                    .filters(f -> f.rewritePath("/case/(.*)", "/$1"))
                    .uri(uriConfiguration.getCaseServerBaseUri())
            )
            .build();
    }
}

@ConfigurationProperties
class UriConfiguration {
    @Value("${backing-services.case.base-uri:http://case-server/}") String caseServerBaseUri;
    @Value("${backing-services.study-server.base-uri:http://study-server/}") String studyServerBaseUri;

    public String getCaseServerBaseUri() {
        return caseServerBaseUri;
    }

    public void setCaseServerBaseUri(String caseServerBaseUri) {
        this.caseServerBaseUri = caseServerBaseUri;
    }

    public String getStudyServerBaseUri() {
        return studyServerBaseUri;
    }

    public void setStudyServerBaseUri(String studyServerBaseUri) {
        this.studyServerBaseUri = studyServerBaseUri;
    }
}
