/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.gridsuite.gateway.services.CacheService;
import org.gridsuite.gateway.services.GatewayService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import static org.gridsuite.gateway.config.GatewayConfig.HEADER_USER_ID;
import static org.gridsuite.gateway.services.GatewayService.CACHE_NAME;
/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
public class TokenValidatorGlobalPreFilter extends AbstractGlobalPreFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);
    public static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted : {}";

    private final GatewayService gatewayService;

    private final CacheService cacheService;

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    public TokenValidatorGlobalPreFilter(GatewayService gatewayService, CacheService cacheService) {
        this.gatewayService = gatewayService;
        this.cacheService = cacheService;
    }

    @Override
    public int getOrder() {
        // Before ElementAccessControllerGlobalPreFilter to enforce authentication
        return Ordered.LOWEST_PRECEDENCE - 3;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());
        ServerHttpRequest req = exchange.getRequest();
        List<String> ls = req.getHeaders().get("Authorization");
        List<String> queryls = req.getQueryParams().get("access_token");

        if (ls == null && queryls == null) {
            LOGGER.info("{}: 401 Unauthorized, Authorization header or access_token query parameter is required",
                exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        // For now we only handle one token. If needed, we can adapt this code to check
        // multiple tokens and accept the connection if at least one of them is valid
        String token;
        if (ls != null) {
            String authorization = ls.get(0);
            List<String> arr = Arrays.asList(authorization.split(" "));

            if (arr.size() != 2 || !arr.get(0).equals("Bearer")) {
                LOGGER.info("{}: 400 Bad Request, incorrect Authorization header value",
                    exchange.getRequest().getPath());
                return completeWithCode(exchange, HttpStatus.BAD_REQUEST);
            }

            token = arr.get(1);
        } else {
            token = queryls.get(0);
        }

        JWT jwt;
        JWTClaimsSet jwtClaimsSet;
        try {
            jwt = JWTParser.parse(token);
            jwtClaimsSet = jwt.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            // Invalid plain JOSE object encoding
            LOGGER.info("{}: 401 Unauthorized, Invalid plain JOSE object encoding", exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        LOGGER.debug("checking issuer");
        if (allowedIssuers.stream().noneMatch(iss -> jwtClaimsSet.getIssuer().startsWith(iss))) {
            LOGGER.info("{}: 401 Unauthorized, {} Issuer is not in the issuers white list", exchange.getRequest().getPath(), jwtClaimsSet.getIssuer());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        try {
            JWT idToken = JWTParser.parse(token);
            Issuer iss = new Issuer(jwt.getJWTClaimsSet().getIssuer());
            ClientID clientID = new ClientID(jwt.getJWTClaimsSet().getAudience().get(0));

            JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());
            URL jwkSetURL = new URL(gatewayService.getJwksUrl(jwt.getJWTClaimsSet().getIssuer()));

            // Create validator for signed ID tokens
            IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

            validator.validate(idToken, null);
            // we can safely trust the JWT
            LOGGER.debug("Token verified, it can be trusted");

            //we add the subject header
            exchange.getRequest()
                .mutate()
                .headers(h -> h.set(HEADER_USER_ID, jwtClaimsSet.getSubject()));
        } catch (JOSEException | BadJOSEException err) {
            try {
                cacheService.evictSingleCacheValueByKey(CACHE_NAME, jwt.getJWTClaimsSet().getIssuer());
                gatewayService.getJwksUrl(jwt.getJWTClaimsSet().getIssuer());
            } catch (ParseException e) {
                LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, exchange.getRequest().getPath(), e.getMessage());
                return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
            }
            LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, exchange.getRequest().getPath(), err.getMessage());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        } catch (ParseException | MalformedURLException e) {
            LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, exchange.getRequest().getPath(), e.getMessage());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }
        return chain.filter(exchange);
    }
}

