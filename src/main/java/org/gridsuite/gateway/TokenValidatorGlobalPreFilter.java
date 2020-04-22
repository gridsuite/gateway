/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.nimbusds.jose.JWSAlgorithm;
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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URL;
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

        if (allowedIssuers.stream().noneMatch(iss -> jwtClaimsSet.getIssuer().startsWith(iss))) {
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

            IDTokenClaimsSet claims = validator.validate(idToken, null);
            // we can safely trust the JWT
            LOGGER.debug("Token verified, it can be trusted");
        } catch (Exception e) {
            LOGGER.debug("The token cannot be trusted");
            throw new GatewayException("The token cannot be trusted : " + e.getMessage());
        }
        return chain.filter(exchange);
    }
}

