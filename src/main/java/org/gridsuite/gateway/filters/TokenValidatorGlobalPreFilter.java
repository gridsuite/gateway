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
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import lombok.AllArgsConstructor;
import lombok.Getter;
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

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
public class TokenValidatorGlobalPreFilter extends AbstractGlobalPreFilter {

    public static final String UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING = "{}: 401 Unauthorized, Invalid plain JOSE object encoding";
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);
    public static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted : {}";
    public static final String CACHE_OUTDATED = "{}: Bad JSON Object Signing and Encryption, cache outdated : {}";
    private final GatewayService gatewayService;

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    private Map<String, JWKSet> jwkSetCache = new ConcurrentHashMap<>();
    private Map<String, String> jwkUriCache = new ConcurrentHashMap<>();

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
        String cacheURi = jwkUriCache.get(iss.getValue());
        Mono<String> fetchedUri = gatewayService.getJwksUrl(jwtClaimsSet.getIssuer()).doOnNext(uri -> jwkUriCache.put(iss.getValue(), uri));
        Mono<String> jwkSetUri = cacheURi != null ? Mono.just(cacheURi) : fetchedUri;
        return jwkSetUri.flatMap(uri -> proceedFilter(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, iss, clientID, jwsAlg, uri)));

    }

    private Mono<Void> validate(FilterInfos filterInfos, JWKSet jwkset) throws BadJOSEException, JOSEException {

        // Create validator for signed ID tokens
        IDTokenValidator validator = new IDTokenValidator(filterInfos.getIss(), filterInfos.getClientID(), filterInfos.getJwsAlg(), jwkset);

        validator.validate(filterInfos.getJwt(), null);
        // we can safely trust the JWT
        LOGGER.debug("Token verified, it can be trusted");

        //we add the subject header
        filterInfos.getExchange().getRequest()
                .mutate()
                .headers(h -> h.set(HEADER_USER_ID, filterInfos.getJwtClaimsSet().getSubject()));

        return filterInfos.getChain().filter(filterInfos.getExchange());
    }

    /**
     * <pre>check jwkset if exist in cache then call validate otherwise download new jwkset and refill map then call validate</pre>
     * => case of BadJOSEException: remove outdated cache and retry same process
     * <ul>
     *  <li>BadJOSEException: Bad JSON Object Signing and Encryption (JOSE) exception.</li>
     *  <li>BadJWSException: Bad JSON Web Signature (JWS) exception. Used to indicate an invalid signature or hash-based message authentication code (HMAC).</li>
     *  <li>JOSEException: Javascript Object Signing and Encryption (JOSE) exception. Used to indicate an invalid jwt type.</li>
     * </ul>
     * @param  filterInfos
     * @return Mono<Void>
     */
    Mono<Void> proceedFilter(FilterInfos filterInfos) {

        JWKSet jwksCache = jwkSetCache.get(filterInfos.getIss().getValue());
        // check if jwkset exists in cache
        if (jwksCache == null) {
            // download public keys and cache it into ConcurrentHashMap
            return gatewayService.getJwkSet(filterInfos.getJwkSetUri()).flatMap(jwksString -> {
                JWKSet jwkSet = null;
                try {
                    jwkSet = JWKSet.parse(jwksString);
                    jwkSetCache.put(filterInfos.getIss().getValue(), jwkSet);
                } catch (ParseException e) {
                    jwkUriCache.remove(filterInfos.getIss().getValue());
                    LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, filterInfos.getExchange().getRequest().getPath());
                    return completeWithCode(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
                }
                try {
                    return validate(filterInfos, jwkSet);
                } catch (BadJOSEException | JOSEException e) {
                    LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.getExchange().getRequest().getPath());
                    return completeWithCode(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
                }
            });
        } else {
            try {
                return validate(filterInfos, jwksCache);
            } catch (BadJOSEException e) {
                LOGGER.info(CACHE_OUTDATED, filterInfos.getExchange().getRequest().getPath());
                jwkSetCache.remove(filterInfos.getIss().getValue());
                return this.proceedFilter(new FilterInfos(filterInfos.getExchange(), filterInfos.getChain(), filterInfos.getJwt(), filterInfos.getJwtClaimsSet(), filterInfos.getIss(), filterInfos.getClientID(), filterInfos.getJwsAlg(), filterInfos.getJwkSetUri()));
            } catch (JOSEException e) {
                LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.getExchange().getRequest().getPath());
                return completeWithCode(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
            }
        }
    }

    @AllArgsConstructor
    @Getter
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
