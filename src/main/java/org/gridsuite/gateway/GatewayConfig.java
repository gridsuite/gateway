/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
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

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
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

    @Component
    public static class TokenValidatorGlobalPreFilter implements GlobalFilter {
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            LOGGER.debug("checking authorization");
            List<String> ls = exchange.getRequest().getHeaders().get("Authorization");
            assert ls != null;
            RSAPublicKey pubKey = null;

            String authorization = ls.get(0);
            String token = authorization.split(" ")[1];
            String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq83bh5xttYemaU7RtlEi2GwT/aGg9YCyK1hlnFrREXOSJlV0g6mlH+w2jA07TD0qFHeoiOXVONL8CLaDoxCkIwx7S8RulgXTffjjKWMM+2q8fC7wCktTCagpegwVMfcwP5SlxbbZrQK5GqCeX343+5kKBRhi2FrbNBpkUgBWFTVSfn0r6+eZd3DcuCESuV+dDaTVxnWlm1vsECnfUea9zeF/Qcf196oBg/yPBXbURT7eM4G1y5/bEbmigVi47M8wNnp6GIez4YyTlpJroGTIhVzoCwtCMg3bO2w7KYN0nK7wHnXq5Hl0nn+oJHv0A8XcLDpWxR9+GYNBa/erpAKJAQIDAQAB";


            try {
                JWT idToken = JWTParser.parse(token);

                // The required parameters
                Issuer iss = new Issuer("http://localhost:8080/auth/realms/chmits");
                ClientID clientID = new ClientID("spa");
                JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
                URL jwkSetURL = null;
                try {
                    jwkSetURL = new URL("http://localhost:8080/auth/realms/chmits/protocol/openid-connect/certs");
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }

                // Create validator for signed ID tokens
                IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);

                IDTokenClaimsSet claims  = validator.validate(idToken, null);
                LOGGER.debug("Cool");
            } catch (Exception e) {
                e.printStackTrace();
            }


            KeyFactory kf = null;
            try {
                kf = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                LOGGER.debug("No Such Algorithm Exception" + e.getMessage());
            }
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            try {
                assert kf != null;
                pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
            } catch (InvalidKeySpecException e) {
                LOGGER.debug("Invalid public key" + e.getMessage());
            }
            Jws<Claims> jws;
            try {
                jws = Jwts.parserBuilder()
                        .setSigningKey(pubKey)
                        .build()
                        .parseClaimsJws(token);
                // we can safely trust the JWT
                LOGGER.debug("The token is valid");
            } catch (JwtException ex) {       // (5)
                LOGGER.debug("The token cannot be trusted");
                throw new IllegalArgumentException("The token cannot be trusted");
            }
            return chain.filter(exchange);
        }
    }

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            .route(p -> p
                    .path("/study/**")
                    .filters(f ->
                            //f.hystrix(config -> config.setName("study")
                            //        .setFallbackUri("forward:/studyFallback"))
                            f.rewritePath("/study/(.*)", "/$1")
                    )
                    .uri(studyServerBaseUri)
            )
            .route(p -> p
                    .path("/case/**")
                    .filters(f -> f.hystrix(config -> config.setName("study").setFallbackUri("forward:/caseFallback"))
                            .rewritePath("/case/(.*)", "/$1")
                    )
                    .uri(caseServerBaseUri)
            )
            .build();
    }
}
