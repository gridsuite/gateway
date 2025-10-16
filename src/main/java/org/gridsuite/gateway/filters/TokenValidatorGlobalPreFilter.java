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
import org.gridsuite.gateway.dto.TokenIntrospection;
import org.gridsuite.gateway.services.UserAdminService;
import org.gridsuite.gateway.services.UserIdentityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
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

import static org.gridsuite.gateway.GatewayConfig.HEADER_ROLES;
import static org.gridsuite.gateway.GatewayConfig.HEADER_USER_ID;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@Component
public class TokenValidatorGlobalPreFilter extends AbstractGlobalPreFilter {

    public static final String UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING = "{}: 401 Unauthorized, Invalid plain JOSE object encoding or inactive opaque token";
    public static final String PARSING_ERROR = "{}: 500 Internal Server Error, error has been reached unexpectedly while parsing";
    public static final String UNAUTHORIZED_AUDIENCE_NOT_ALLOWED = "401 Unauthorized, {} Audience is not in the audiences white list";
    public static final String UNAUTHORIZED_CLIENT_NOT_ALLOWED = "401 Unauthorized, {} Client ID is not in the allowed clients list";

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenValidatorGlobalPreFilter.class);
    public static final String UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED = "{}: 401 Unauthorized, The token cannot be trusted";
    public static final String CACHE_OUTDATED = "{}: Bad JSON Object Signing and Encryption, cache outdated";
    private final GatewayService gatewayService;
    private final UserIdentityService userIdentityService;

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    @Value("${allowed-audiences:}")
    private List<String> allowedAudiences;

    @Value("${allowed-clients:}")
    private List<String> allowedClients;

    @Value("${storeIdToken:false}")
    private boolean storeIdTokens;

    private Map<String, JWKSet> jwkSetCache = new ConcurrentHashMap<>();

    public TokenValidatorGlobalPreFilter(GatewayService gatewayService, UserIdentityService userIdentityService, UserAdminService userAdminService) {
        super(userAdminService);
        this.gatewayService = gatewayService;
        this.userIdentityService = userIdentityService;
    }

    @Override
    public int getOrder() {
        // Before ElementAccessControllerGlobalPreFilter to enforce authentication
        return Ordered.LOWEST_PRECEDENCE - 4;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        LOGGER.debug("Filter : {}", getClass().getSimpleName());
        ServerHttpRequest req = exchange.getRequest();
        List<String> ls = req.getHeaders().get(HttpHeaders.AUTHORIZATION);
        List<String> queryls = req.getQueryParams().get("access_token");

        if (ls == null && queryls == null) {
            LOGGER.info("{}: 401 Unauthorized, Authorization header or access_token query parameter is required",
                exchange.getRequest().getPath());
            return completeWithError(exchange, HttpStatus.UNAUTHORIZED);
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
                return completeWithError(exchange, HttpStatus.BAD_REQUEST);
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

            LOGGER.debug("checking issuer");
            if (allowedIssuers.stream().noneMatch(iss -> jwtClaimsSet.getIssuer().startsWith(iss))) {
                LOGGER.info("{}: 401 Unauthorized, {} Issuer is not in the issuers white list", exchange.getRequest().getPath(), jwtClaimsSet.getIssuer());
                return completeWithError(exchange, HttpStatus.UNAUTHORIZED);
            }

            if (!isValidAudienceOrClientId(jwtClaimsSet)) {
                return completeWithError(exchange, HttpStatus.UNAUTHORIZED);
            }

            Issuer iss = new Issuer(jwtClaimsSet.getIssuer());
            ClientID clientID;
            List<String> audiences = jwtClaimsSet.getAudience();
            if (audiences != null && !audiences.isEmpty()) {
                clientID = new ClientID(audiences.getFirst());
            } else {
                // Since audience validation failed but we're here, we must have a valid client_id
                String clientIdClaim = (String) jwtClaimsSet.getClaim("client_id");
                clientID = new ClientID(clientIdClaim);
            }

            JWSAlgorithm jwsAlg = JWSAlgorithm.parse(jwt.getHeader().getAlgorithm().getName());
            return proceedFilter(new FilterInfos(exchange, chain, jwt, jwtClaimsSet, iss, clientID, jwsAlg));
        } catch (java.text.ParseException e) {
            // Invalid plain JOSE object encoding
            // Don't print the full stacktrace here for less verbose logs,
            // we have enough context with just the message
            LOGGER.debug("JWTParser.parse ParseException, will attempt to use as opaque token: ({})", e.getMessage());
            // TODO try more than just the first issuer here ? get the issuer from the client ?
            return validateOpaqueReferenceToken(allowedIssuers.get(0), token, exchange, chain);
        }
    }

    private Mono<Void> validateOpaqueReferenceToken(String issBaseUri, String token, ServerWebExchange exchange,
            GatewayFilterChain chain) {
        // TODO CACHE the two requests
        return gatewayService.getOpaqueTokenIntrospectionUri(issBaseUri)
                .flatMap(uri -> gatewayService.getOpaqueTokenIntrospection(uri, token))
                .flatMap((TokenIntrospection tokenIntrospection) -> {
                    // Check client ID against allowedClients
                    String clientId = tokenIntrospection.getClientId();
                    if (!isValidClientId(clientId)) {
                        LOGGER.info(UNAUTHORIZED_CLIENT_NOT_ALLOWED, clientId);
                        return completeWithError(exchange, HttpStatus.UNAUTHORIZED);
                    }

                    if (tokenIntrospection.getActive()) {
                        LOGGER.debug("Opaque Token verified, it can be trusted");

                        // TODO really add the client_id header instead of userid
                        // Build mutated request with userId header
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header(HEADER_USER_ID, tokenIntrospection.getClientId())
                                .build();

                        // Create new exchange with mutated request
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(mutatedRequest)
                                .build();

                        // Pass mutated exchange to chain
                        return chain.filter(mutatedExchange);
                    } else {
                        LOGGER.info(UNAUTHORIZED_INVALID_PLAIN_JOSE_OBJECT_ENCODING, exchange.getRequest().getPath());
                        return completeWithError(exchange, HttpStatus.UNAUTHORIZED);
                    }
                });
    }

    /**
     * Validates a token's audience or client ID depending on token type.
     *
     * JWT ID tokens (representing end users) typically contain an 'aud' claim that needs validation.
     * JWT access tokens may not have an 'aud' claim but instead use a 'client_id' claim.
     *
     * We first try to validate the audience. Only if no valid audience is found, we fall back to
     * client ID validation. This allows both token types to work with the gateway.
     *
     * IMPORTANT NOTES:
     * - Currently, we only allow GridSuite audience tokens in the allowedAudiences configuration
     * - If we want to allow other frontend applications to access this API:
     *   a) This validation logic needs to be reviewed and possibly expanded
     *   b) The CORS strategy would need to be modified accordingly to allow those origins
     *
     * @param jwtClaimsSet The JWT claims set
     * @return true if validation passes, false otherwise
     */
    private boolean isValidAudienceOrClientId(JWTClaimsSet jwtClaimsSet) {
        if (allowedAudiences.isEmpty() && allowedClients.isEmpty()) {
            LOGGER.debug("Bypassing audience and client ID validation as both allowed lists are empty");
            return true;
        }

        LOGGER.debug("checking audience or client ID");
        List<String> tokenAudiences = jwtClaimsSet.getAudience();
        if (tokenAudiences != null && !tokenAudiences.isEmpty()) {
            boolean audienceMatched = tokenAudiences.stream().anyMatch(aud -> allowedAudiences.contains(aud));
            if (audienceMatched) {
                LOGGER.debug("Audience validation successful");
                return true;
            }
            LOGGER.info(UNAUTHORIZED_AUDIENCE_NOT_ALLOWED, tokenAudiences);
            return false;
        }
        // If there is no audience at all in the token we can try a fallback
        LOGGER.debug("Audience validation failed for audiences: {}, trying client ID as fallback", tokenAudiences);
        String clientIdClaim = (String) jwtClaimsSet.getClaim("client_id");
        if (isValidClientId(clientIdClaim)) {
            LOGGER.debug("Client ID validation successful");
            return true;
        }
        LOGGER.info(UNAUTHORIZED_CLIENT_NOT_ALLOWED, jwtClaimsSet.getClaim("client_id"));
        return false;
    }

    /**
     * Validates whether a client ID is in the list of allowed clients.
     *
     * @param clientId The client ID to validate
     * @return true if validation passes, false otherwise
     */
    private boolean isValidClientId(String clientId) {
        if (allowedClients.isEmpty()) {
            return true;
        }
        return clientId != null && allowedClients.contains(clientId);
    }

    private Mono<Void> validate(FilterInfos filterInfos, JWKSet jwkset) throws BadJOSEException, JOSEException {

        // Create validator for signed ID tokens
        // IMPORTANT: IDTokenValidator strictly enforces OpenID Connect standards including
        // the mandatory presence of the 'aud' (audience) claim. Even though our code has a
        // fallback mechanism in isValidAudienceOrClientId() to validate tokens with only
        // client_id claims, the IDTokenValidator will still throw BadJOSEException with
        // message "Missing JWT audience (aud) claim" for any token without an audience.
        //
        // This creates a behavior inconsistency: tokens with valid client_id but no audience
        // will pass our custom validation (isValidAudienceOrClientId) but will be rejected here.
        //
        // Alternative approaches if client_id-only tokens must be fully supported:
        // Use DefaultJWTClaimsVerifier instead of IDTokenValidator (https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens)
        IDTokenValidator validator = new IDTokenValidator(filterInfos.getIss(), filterInfos.getClientID(), filterInfos.getJwsAlg(), jwkset);

        validator.validate(filterInfos.getJwt(), null);
        // we can safely trust the JWT
        LOGGER.debug("JWT Token verified, it can be trusted");

        // TODO how do we differentiate between JWT Access Token (no user information)
        // and JWT ID tokens with little or no user information for which we use
        // defaults like the sub. Do we need the storage server to always accumulate
        // the data to guard against access token clearing data from a previous id token ?
        // or do we need an explicit endpoint where our front sends idtoken (the frontend knows
        // whether it has requested an access token or and id token) ? but then we maybe miss
        // some tokens if for some reason the frontend doesn't send the token, whereas here
        // we are guaranteed that we receive the token.
        if (storeIdTokens) {
            userIdentityService.storeToken(filterInfos.getJwtClaimsSet().getSubject(), filterInfos.getJwtClaimsSet())
                    // send in the background and don't wait for the result. This is the hot path on
                    // all requests !
                    .subscribe();
        }

        ServerWebExchange exchange = filterInfos.getExchange();
        //we add the subject header
        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                .header(HEADER_USER_ID, filterInfos.getJwtClaimsSet().getSubject());

        Object profileClaim = filterInfos.getJwtClaimsSet().getClaim("profile");
        if (profileClaim != null) {
            requestBuilder.header(HEADER_ROLES, profileClaim.toString());
        }
        ServerHttpRequest mutatedRequest = requestBuilder.build();

        // Create a new exchange with the mutated request
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return filterInfos.getChain().filter(mutatedExchange);
    }

    /**
     * <pre>check jwkset if exist in cache then call validate otherwise download new JWKSet and refill map then call validate</pre>
     * => case of BadJOSEException: remove outdated cache and retry same process
     * <ul>
     *  <li>BadJOSEException: Bad JSON Object Signing and Encryption (JOSE) exception.</li>
     *  <li>BadJWSException (Subclass of BadJOSEException) : Bad JSON Web Signature (JWS) exception. Used to indicate an invalid signature or hash-based message authentication code (HMAC).</li>
     *  <li>JOSEException: Javascript Object Signing and Encryption (JOSE) exception. Used to indicate an invalid jwt type.</li>
     * </ul>
     * @param  filterInfos
     * @return Mono<Void>
     */
    Mono<Void> proceedFilter(FilterInfos filterInfos) {

        JWKSet jwksCache = jwkSetCache.get(filterInfos.getIss().getValue());
        // check if jwkset exists in cache
        if (jwksCache != null) {
            return tryValidate(filterInfos, jwksCache, true);
        } else {
            // get Jwks Url
            return gatewayService.getJwksUrl(filterInfos.getIss().getValue()).flatMap(uri ->
                // download public keys and cache it into ConcurrentHashMap
                gatewayService.getJwkSet(uri).flatMap(jwksString -> {
                    JWKSet jwkSet = null;
                    try {
                        jwkSet = JWKSet.parse(jwksString);
                        jwkSetCache.put(filterInfos.getIss().getValue(), jwkSet);
                    } catch (ParseException e) {
                        LOGGER.info(PARSING_ERROR, filterInfos.getExchange().getRequest().getPath());
                        return completeWithError(filterInfos.getExchange(), HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                    return tryValidate(filterInfos, jwkSet, false);
                })
            );
        }
    }

    private Mono<Void> tryValidate(FilterInfos filterInfos, JWKSet jwksCache, boolean evict) {
        try {
            return validate(filterInfos, jwksCache);
        } catch (JOSEException | BadJOSEException e) {
            if (evict && e instanceof BadJOSEException) {
                LOGGER.info(CACHE_OUTDATED, filterInfos.getExchange().getRequest().getPath());
                jwkSetCache.remove(filterInfos.getIss().getValue());
                return this.proceedFilter(filterInfos);
            } else {
                LOGGER.info(UNAUTHORIZED_THE_TOKEN_CANNOT_BE_TRUSTED, filterInfos.getExchange().getRequest().getPath());
                return completeWithError(filterInfos.getExchange(), HttpStatus.UNAUTHORIZED);
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
    }
}
