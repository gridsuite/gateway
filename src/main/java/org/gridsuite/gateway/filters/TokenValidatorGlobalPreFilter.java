/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.filters;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.gridsuite.gateway.GatewayService;
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

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
public class TokenValidatorGlobalPreFilter extends AbstractGlobalPreFilter {

    public static final String UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING = "{}: 401 Unauthorized, Invalid plain JOSE object encoding";
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);
    public static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted : {}";

    private final GatewayService gatewayService;

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    private Map<String, JWKSet> jwkSetCache = new HashMap<>();
    private Map<String, String> jwkUriCache = new HashMap<>();

    public TokenValidatorGlobalPreFilter(GatewayService gatewayService) {
        this.gatewayService = gatewayService;
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
            LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, exchange.getRequest().getPath());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        LOGGER.debug("checking issuer");

        if (allowedIssuers.stream().noneMatch(iss -> jwtClaimsSet.getIssuer().startsWith(iss))) {
            LOGGER.info("{}: 401 Unauthorized, {} Issuer is not in the issuers white list", exchange.getRequest().getPath(), jwtClaimsSet.getIssuer());
            return completeWithCode(exchange, HttpStatus.UNAUTHORIZED);
        }

        Issuer iss = new Issuer(jwtClaimsSet.getIssuer());
        ClientID clientID = new ClientID(jwtClaimsSet.getAudience().get(0));

        JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());
        return jwkUriCache.get(iss.getValue()) != null ? proceedFilter(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, iss, clientID, jwsAlg, jwkUriCache.get(iss.getValue()))) : gatewayService.getJwksUrl(jwtClaimsSet.getIssuer())
                .flatMap(jwkSetUri -> {
                    jwkUriCache.put(iss.getValue(), jwkSetUri);
                    return proceedFilter(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, iss, clientID, jwsAlg, jwkSetUri));
                });
    }

    private Mono<Void> validate(FilterInfos filterInfos) throws BadJOSEException, JOSEException {

        // Create validator for signed ID tokens
        IDTokenValidator validator = new IDTokenValidator(filterInfos.getIss(), filterInfos.getClientID(), filterInfos.getJwsAlg(), jwkSetCache.get(filterInfos.getIss().getValue()));

        validator.validate(filterInfos.getJwt(), null);
        // we can safely trust the JWT
        LOGGER.debug("Token verified, it can be trusted");

        //we add the subject header
        filterInfos.getExchange().getRequest()
                .mutate()
                .headers(h -> h.set(HEADER_USER_ID, filterInfos.getJwtClaimsSet().getSubject()));

        return filterInfos.getChain().filter(filterInfos.getExchange());
    }

    Mono<Void> proceedFilter(FilterInfos filterInfos) {
        // if jwkset source not found in cache
        if (jwkSetCache.get(filterInfos.getIss().getValue()) == null) {
            try {
                // download public keys and cache it
                RemoteJWKSet<SecurityContext> jwkSource = new RemoteJWKSet<>(new URL(filterInfos.getJwkSetUri()), new DefaultResourceRetriever());
                JWKSet jwksSet = JWKSet.parse(jwkSource.getResourceRetriever().retrieveResource(new URL(filterInfos.getJwkSetUri())).getContent());
                jwkSetCache.put(filterInfos.getIss().getValue(), jwksSet);
                validate(filterInfos);
            } catch (BadJOSEException | JOSEException | IOException e) {
                jwkUriCache.remove(filterInfos.getIss().getValue());
                LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.getExchange().getRequest().getPath());
                return completeWithCode(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
            } catch (ParseException e) {
                jwkUriCache.remove(filterInfos.getIss().getValue());
                LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, filterInfos.getExchange().getRequest().getPath());
                return completeWithCode(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
            }
        } else {
            try {
                validate(filterInfos);
            } catch (BadJOSEException | JOSEException e) {
                jwkSetCache.remove(filterInfos.getIss().getValue());
                return this.proceedFilter(new FilterInfos(filterInfos.getExchange(), filterInfos.getChain(), filterInfos.getJwt(), filterInfos.getJwtClaimsSet(), filterInfos.getIss(), filterInfos.getClientID(), filterInfos.getJwsAlg(), filterInfos.getJwkSetUri()));
            }
        }

        return filterInfos.getChain().filter(filterInfos.getExchange());
    }

    @AllArgsConstructor
    @Getter
    @Setter
    private static class FilterInfos {
        private final ServerWebExchange exchange;
        private final GatewayFilterChain chain;
        private final JWT jwt;
        private final JWTClaimsSet jwtClaimsSet;
        private final Issuer iss;
        private final ClientID clientID;
        private final JWSAlgorithm jwsAlg;
        private final String jwkSetUri;
    }
}

