/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
public class TokenValidatorGlobalPreFilter implements GlobalFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    @Autowired
    private final GatewayService gatewayService;

    public TokenValidatorGlobalPreFilter(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("checking authorization");
        List<String> ls = exchange.getRequest().getHeaders().get("Authorization");
        if (ls == null) {
            LOGGER.debug("Authorization header is required");
            // set UNAUTHORIZED 401 response and stop the processing
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        LOGGER.debug("checking issuer");
        String authorization = ls.get(0);
        List<String> arr = Arrays.asList(authorization.split(" "));

        if (arr.size() != 2) {
            // set BAD REQUEST 400 response and stop the processing
            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
            return exchange.getResponse().setComplete();
        }

        String token = arr.get(1);
        JWT jwt;
        JWTClaimsSet jwtClaimsSet;
        try {
            jwt = JWTParser.parse(token);
            jwtClaimsSet = jwt.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            // Invalid plain JOSE object encoding
            LOGGER.debug("Invalid plain JOSE object encoding");
            // set UNAUTHORIZED 401 response and stop the processing
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        if (allowedIssuers.stream().noneMatch(iss -> jwtClaimsSet.getIssuer().startsWith(iss))) {
            LOGGER.debug(jwtClaimsSet.getIssuer() + " Issuer is not in the issuers white list");
            // set UNAUTHORIZED 401 response and stop the processing
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            JWT idToken = JWTParser.parse(token);
            Issuer iss = new Issuer(jwt.getJWTClaimsSet().getIssuer());
            ClientID clientID = new ClientID(jwt.getJWTClaimsSet().getAudience().get(0));

            JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());
            URL jwkSetURL = null;

            jwkSetURL = new URL(gatewayService.getJwksUrl(jwt.getJWTClaimsSet().getIssuer()));

            // Create validator for signed ID tokens
            IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

            IDTokenClaimsSet claims = validator.validate(idToken, null);
            // we can safely trust the JWT
            LOGGER.debug("Token verified, it can be trusted");
        } catch (JOSEException | BadJOSEException | ParseException | MalformedURLException e) {
            LOGGER.debug("The token cannot be trusted : " + e.getMessage());
            // set UNAUTHORIZED 401 response and stop the processing
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }
}

