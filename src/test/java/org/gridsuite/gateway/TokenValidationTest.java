/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.github.tomakehurst.wiremock.client.VerificationException;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.responsetemplating.ResponseTemplateTransformer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.cloud.contract.wiremock.WireMockConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.socket.client.StandardWebSocketClient;
import org.springframework.web.reactive.socket.client.WebSocketClient;
import reactor.core.publisher.Mono;
import wiremock.com.github.jknack.handlebars.Helper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.gridsuite.gateway.filters.TokenValidatorGlobalPreFilter.ACCESS_TOKEN_SHARE_COOKIE_NAME;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"powsybl.services.case-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.study-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.merge-orchestrator-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.merge-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.directory-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.actions-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.study-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.config-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.config-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.directory-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.explore-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.cgmes-boundary-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.dynamic-mapping-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.filter-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.report-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.network-modification-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.user-admin-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.sensitivity-analysis-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.user-identity-server.base-uri=http://localhost:${wiremock.server.port}",
        "allowed-issuers=http://localhost:${wiremock.server.port}",
        "allowed-audiences=test.app,chmits",
        "allowed-clients=chmits",
    })
@AutoConfigureWireMock(port = 0)
class TokenValidationTest {

    @Value("${wiremock.server.port}")
    private int port;

    @LocalServerPort
    private String localServerPort;

    private String token;
    private String token2;
    private String expiredToken;
    private String tokenWithNotAllowedIssuer;
    private String tokenWithNotAllowedAudience;
    private String tokenWithValidClientId;
    private String tokenWithInvalidClientId;
    private RSAKey rsaKey;
    private RSAKey rsaKey2;

    @Autowired
    private WebTestClient webClient;

    @BeforeEach
    void prepareToken() throws JOSEException {
        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();

        RSAKey rsaJWK2 = new RSAKeyGenerator(2048)
                .keyID("111")
                .generate();

        rsaKey = rsaJWK.toPublicJWK();
        rsaKey2 = rsaJWK2.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);
        JWSSigner signer2 = new RSASSASigner(rsaJWK2);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("chmits")
                .audience("test.app")
                .issuer("http://localhost:" + port)
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Prepare JWT with claims set for token with invalid audience
        JWTClaimsSet claimsSetForInvalidAudience = new JWTClaimsSet.Builder()
                .subject("chmits")
                .audience("unauthorized.app")
                .issuer("http://localhost:" + port)
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Prepare JWT with claims set
        JWTClaimsSet claimsSetForExpiredToken = new JWTClaimsSet.Builder()
                .subject("chmits")
                .audience("test.app")
                .issuer("http://localhost:" + port)
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() - 1000 * 60 * 60))
                .build();

        // Prepare JWT with claims set
        JWTClaimsSet claimsSetForTokenWithIssuerNotAllowed = new JWTClaimsSet.Builder()
                .subject("chmits")
                .audience("test.app")
                .issuer("http://notAllowedissuer")
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() - 1000 * 60 * 60))
                .build();

        // Prepare JWT with claims set for token with valid client_id but no audience
        JWTClaimsSet claimsSetValidClientId = new JWTClaimsSet.Builder()
                .subject("chmits")
                .issuer("http://localhost:" + port)
                .claim("client_id", "chmits") // Valid client_id (in allowedClients)
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        // Prepare JWT with claims set for token with invalid client_id and no audience
        JWTClaimsSet claimsSetInvalidClientId = new JWTClaimsSet.Builder()
                .subject("chmits")
                .issuer("http://localhost:" + port)
                .claim("client_id", "invalid-client") // Invalid client_id (not in allowedClients)
                .issueTime(new Date())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet);
        SignedJWT signedJWT2 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK2.getKeyID()).build(), claimsSet);
        SignedJWT signedJWTExpired = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForExpiredToken);
        SignedJWT signedJWTWithIssuerNotAllowed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForTokenWithIssuerNotAllowed);
        SignedJWT signedJWTWithInvalidAudience = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForInvalidAudience);
        SignedJWT signedJWTValidClientId = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetValidClientId);
        SignedJWT signedJWTInvalidClientId = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetInvalidClientId);

        // Compute the RSA signature
        signedJWT.sign(signer);
        signedJWT2.sign(signer2);
        signedJWTExpired.sign(signer);
        signedJWTWithIssuerNotAllowed.sign(signer);
        signedJWTWithInvalidAudience.sign(signer);
        signedJWTValidClientId.sign(signer);
        signedJWTInvalidClientId.sign(signer);

        token = signedJWT.serialize();
        token2 = signedJWT2.serialize();
        expiredToken = signedJWTExpired.serialize();
        tokenWithNotAllowedIssuer = signedJWTWithIssuerNotAllowed.serialize();
        tokenWithNotAllowedAudience = signedJWTWithInvalidAudience.serialize();
        tokenWithValidClientId = signedJWTValidClientId.serialize();
        tokenWithInvalidClientId = signedJWTInvalidClientId.serialize();
    }

    /**
     * Splits {@code token} into its two base64 XOR shares, mirroring what the frontend can do.
     *
     * <p>Note: for simplicity because of how these tests are architected (the token contains
     * wiremock's dynamic port), we rewrite this small client code and compute this dynamically
     * instead of hardcoding an example token + its shares as string constants.
     */
    private static String[] splitToken(String token) {
        byte[] tokenBytes = token.getBytes(StandardCharsets.UTF_8);
        byte[] random = new byte[tokenBytes.length];
        new SecureRandom().nextBytes(random);
        byte[] xored = new byte[tokenBytes.length];
        for (int i = 0; i < tokenBytes.length; i++) {
            xored[i] = (byte) (tokenBytes[i] ^ random[i]);
        }
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return new String[] {encoder.encodeToString(random), encoder.encodeToString(xored)};
    }

    /**
     * Drives a websocket handshake through the gateway, authenticated either with the whole
     * (unsplit) {@code token} in the access_token query parameter ({@code splitAuth} false), or
     * with {@code token} XOR-split across the AccessTokenShare cookie and the
     * access_token_share query parameter ({@code splitAuth} true).
     */
    private void testWebsocket(String name, boolean splitAuth, String token) throws Exception {
        WebSocketClient client = new StandardWebSocketClient();
        HttpHeaders headers = new HttpHeaders();
        URI uri;
        if (splitAuth) {
            String[] shares = splitToken(token);
            headers.add(HttpHeaders.COOKIE, ACCESS_TOKEN_SHARE_COOKIE_NAME + "=" + shares[0]);
            uri = URI.create("ws://localhost:" + this.localServerPort + "/" + name + "/notify?access_token_share=" + shares[1]);
        } else {
            uri = URI.create("ws://localhost:" + this.localServerPort + "/" + name + "/notify?access_token=" + token);
        }
        Mono<Void> wsconnection = client.execute(uri, headers, ws -> ws.receive().then());
        wsconnection.subscribe();

        // Busy loop waiting to check that spring-gateway contacted our wiremock server
        // Is there a better way to wait for wiremock to complete the request ?
        boolean done = false;
        for (int i = 0; i < 100; i++) {
            Thread.sleep(10);
            try {
                verify(getRequestedFor(urlPathEqualTo("/notify"))
                        .withHeader(HttpHeaders.CONNECTION, equalTo(HttpHeaders.UPGRADE))
                        .withHeader(HttpHeaders.UPGRADE, equalTo("websocket")));
                done = true;
            } catch (VerificationException e) {
                // nothing to do
            }
            if (done) {
                break;
            }
        }
        if (!done) {
            fail("Wiremock didn't receive the websocket connection");
        }
        try {
            wsconnection.timeout(Duration.ofMillis(100)).block();
            fail("websocket client was closed but should remain open");
        } catch (Exception ignored) {
            //should timeout
        }
    }

    @Test
    // Note: Not sure if it's very useful to test all these routes and various json returns here..
    void gatewayTest() {
        initStubForJwk();

        UUID elementUuid = UUID.randomUUID();

        // Seems unused: no testToken call below ever hits this route.
        stubFor(head(urlPathEqualTo("/v1/elements")).withQueryParam("ids", equalTo(elementUuid.toString())).withPort(port).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()));

        stubFor(get(urlPathEqualTo("/v1/explore/elements/metadata")).withQueryParam("ids", equalTo(elementUuid.toString())).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody(String.format("[{\"elementUuid\" : \"%s\", \"type\" : \"STUDY\", \"subdirectoriesCount\" : \"0\", \"specificMetadata\" : {\"id\" : \"%s\", \"caseFormat\" : \"IIDM\"}}]",
                        elementUuid, elementUuid))));

        stubFor(get(urlPathEqualTo("/v1/studies/metadata")).withQueryParam("ids", equalTo(elementUuid.toString())).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody(String.format("[{\"id\" : \"%s\", \"caseFormat\" : \"IIDM\"}]", elementUuid))));

        stubFor(get(urlPathEqualTo("/v1/contingency-lists/metadata")).withQueryParam("ids", equalTo(elementUuid.toString())).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody(String.format("[{\"id\" : \"%s\", \"type\" : \"SCRIPT\"}]", elementUuid))));

        stubFor(get(urlPathEqualTo("/v1/filters/metadata")).withQueryParam("ids", equalTo(elementUuid.toString())).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody(String.format("[{\"id\": \"%s\", \"type\" :\"LINE\"}]", elementUuid))));

        stubFor(get(urlPathEqualTo("/v1/root_directories")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"test\"}]")));

        stubFor(get(urlPathEqualTo("/v1/cases")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlPathEqualTo("/v1/parameters")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"theme\": \"dark\"}]")));

        // Seems unused: no testToken call below ever hits this route.
        stubFor(get(urlPathEqualTo("/v1/configs")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"process\": \"TEST\", \"tsos\" : [\"BE\", \"NL\"]}]")));

        // Seems unused: no testToken call below ever hits this route.
        stubFor(get(urlPathEqualTo("/v1/boundaries")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("[{\"name\": \"boundary1\", \"id\" :\"da47a173-22d2-47e8-8a84-aa66e2d0fafb\"}]")));

        stubFor(get(urlPathEqualTo("/mappings")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"mapping1\", \"rules\":[]}]")));

        // Seems unused: no testToken call below ever hits this route.
        stubFor(get(urlPathEqualTo("/v1/reports")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("{\"id\": \"report1\", \"reports\" :[{\"date\":\"2001:01:01T11:11\", \"report\": \"Lets Rock\" }]}")));

        testToken(elementUuid, token, this::authorizationHeaderAuth);
        testToken(elementUuid, token, this::accessTokenQueryParamAuth);
        testToken(elementUuid, token, this::accessTokenShareAuth);
        //TODO are all requests supposed to work with reference tokens from clients ?
        testToken(elementUuid, "clientopaquetoken", this::authorizationHeaderAuth);
        testToken(elementUuid, "clientopaquetoken", this::accessTokenQueryParamAuth);
        testToken(elementUuid, "clientopaquetoken", this::accessTokenShareAuth);
    }

    private static String appendQueryParam(String uri, String name, String value) {
        return uri + (uri.contains("?") ? "&" : "?") + name + "=" + value;
    }

    /**
     * Finishes setting up a request obtained from {@code webClient.get()} - called fresh at every
     * call site in {@link #testToken} - by applying {@code uri} and the auth mode's carrier(s) for
     * {@code token}: the URI alone (access_token query parameter), the URI and a cookie (the split
     * access_token_share cookie + query parameter), or a header alone (Authorization).
     */
    @FunctionalInterface
    private interface AuthSetup {
        WebTestClient.RequestHeadersSpec<?> apply(WebTestClient.RequestHeadersUriSpec<?> request, String uri, String token);
    }

    /**
     * Sets {@code uri} unmodified and carries the whole (unsplit) {@code token} in the
     * Authorization header.
     */
    private WebTestClient.RequestHeadersSpec<?> authorizationHeaderAuth(WebTestClient.RequestHeadersUriSpec<?> request, String uri, String token) {
        return request.uri(uri).header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    /**
     * Carries the whole (unsplit) {@code token} in an access_token query parameter appended to
     * {@code uri}.
     */
    private WebTestClient.RequestHeadersSpec<?> accessTokenQueryParamAuth(WebTestClient.RequestHeadersUriSpec<?> request, String uri, String token) {
        return request.uri(appendQueryParam(uri, "access_token", token));
    }

    /**
     * Carries {@code token} XOR-split across the AccessTokenShare cookie and an
     * access_token_share query parameter appended to {@code uri}.
     */
    private WebTestClient.RequestHeadersSpec<?> accessTokenShareAuth(WebTestClient.RequestHeadersUriSpec<?> request, String uri, String token) {
        String[] shares = splitToken(token);
        return request.uri(appendQueryParam(uri, "access_token_share", shares[1]))
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[0]);
    }

    private void testToken(UUID elementUuid, String token, AuthSetup authSetup) {
        authSetup.apply(webClient.get(), "case/v1/cases", token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("testCase")
                .jsonPath("$[1].name").isEqualTo("testCase2")
                .jsonPath("$[0].format").isEqualTo("XIIDM")
                .jsonPath("$[1].format").isEqualTo("CGMES");

        authSetup.apply(webClient.get(), "study/v1/studies/metadata?ids=" + elementUuid, token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
                .jsonPath("$[0].caseFormat").isEqualTo("IIDM");

        authSetup.apply(webClient.get(), "actions/v1/contingency-lists/metadata?ids=" + elementUuid, token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
                .jsonPath("$[0].type").isEqualTo("SCRIPT");

        authSetup.apply(webClient.get(), "config/v1/parameters", token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].theme").isEqualTo("dark");

        authSetup.apply(webClient.get(), "directory/v1/root_directories", token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("test");

        authSetup.apply(webClient.get(), "dynamic-mapping/mappings", token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("mapping1");

        authSetup.apply(webClient.get(), "filter/v1/filters/metadata?ids=" + elementUuid, token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
            .jsonPath("$[0].type").isEqualTo("LINE");

        authSetup.apply(webClient.get(), "explore/v1/explore/elements/metadata?ids=" + elementUuid, token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].elementUuid").isEqualTo(elementUuid.toString())
            .jsonPath("$[0].type").isEqualTo("STUDY")
            .jsonPath("$[0].subdirectoriesCount").isEqualTo(0);
    }

    @Test
    void testWebsockets() throws Exception {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/notify")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Sec-WebSocket-Accept", "{{{sec-websocket-accept request.headers.Sec-WebSocket-Key}}}")
                .withHeader(HttpHeaders.UPGRADE, "websocket")
                .withHeader(HttpHeaders.CONNECTION, HttpHeaders.UPGRADE)
                .withStatus(101)
                .withStatusMessage("Switching Protocols")));

        // Note: Not sure if it's very useful to test all these routes
        testWebsocket("study-notification", false, token);
        testWebsocket("config-notification", false, token);
        testWebsocket("merge-notification", false, token);
        testWebsocket("directory-notification", false, token);
        testWebsocket("study-notification", true, token);
        testWebsocket("config-notification", true, token);
        testWebsocket("merge-notification", true, token);
        testWebsocket("directory-notification", true, token);
        testWebsocket("study-notification", false, "clientopaquetoken");
        testWebsocket("config-notification", false, "clientopaquetoken");
        testWebsocket("merge-notification", false, "clientopaquetoken");
        testWebsocket("directory-notification", false, "clientopaquetoken");
        testWebsocket("study-notification", true, "clientopaquetoken");
        testWebsocket("config-notification", true, "clientopaquetoken");
        testWebsocket("merge-notification", true, "clientopaquetoken");
        testWebsocket("directory-notification", true, "clientopaquetoken");
    }

    @Test
    void testLoneAccessTokenShareChannelIsAlwaysRejected() {
        initStubForJwk();
        // Needed here (unlike most other tests in this class): the verify(0, ...) below is an
        // exact-count check, so it would be broken by leftover /introspection requests left in
        // WireMock's journal by earlier tests in this class (e.g. testAudienceValidation),
        // since the WireMock server/journal is shared across all @Test methods in this class.
        resetAllRequests();

        stubFor(get(urlPathEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        String[] shares = splitToken(token);

        // Cookie share alone, no access_token_share query param companion: rejected outright,
        // never even reaches token validation - a lone share is never usable by itself.
        webClient
                .get().uri("case/v1/cases")
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[0])
                .exchange()
                .expectStatus().isUnauthorized();

        // Query share alone, no AccessTokenShare cookie companion: same.
        webClient
                .get().uri("case/v1/cases?access_token_share=" + shares[1])
                .exchange()
                .expectStatus().isUnauthorized();

        // Even a genuinely valid whole token alone in the AccessTokenShare cookie (no query
        // companion) is rejected: unlike the deprecated whole-token-in-cookie mode, this cookie
        // is never usable by itself, precisely so that it can't be replayed as ambient authority
        // by a cross-site request an attacker's page could trigger (CSRF).
        webClient
                .get().uri("case/v1/cases")
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, token)
                .exchange()
                .expectStatus().isUnauthorized();

        // None of the above ever reached opaque-token introspection: they're all rejected
        // upfront by the priority chain in filter(), before any token validation is attempted.
        verify(0, postRequestedFor(urlEqualTo("/introspection")));
    }

    @Test
    void testSplitTokenRejectsMismatchedShareLengths() {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        String[] shares = splitToken(token);
        // Truncate the query share by one byte so its decoded length no longer matches the
        // cookie share's: recombination fails and the gateway rejects outright - unlike the
        // access_token query parameter, access_token_share is never meaningful as a whole token
        // by itself, so there's no fallback to attempt.
        byte[] xoredBytes = Base64.getUrlDecoder().decode(shares[1]);
        String truncatedQueryShare = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOf(xoredBytes, xoredBytes.length - 1));

        webClient
                .get().uri("case/v1/cases?access_token_share=" + truncatedQueryShare)
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[0])
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void testSplitTokenRejectsNonBase64AccessTokenShare() {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        String[] shares = splitToken(token);
        // "!" isn't part of the base64url alphabet: Base64.getUrlDecoder() throws
        // IllegalArgumentException, exercising recoverSplitToken's catch block itself - unlike
        // testSplitTokenRejectsMismatchedShareLengths above, whose truncated share still decodes
        // fine and instead exercises the decoded-length mismatch check.
        webClient
                .get().uri("case/v1/cases?access_token_share=not-a-valid-base64!!!")
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[0])
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void testSplitTokenSharesRecombineRegardlessOfOrder() {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/v1/cases")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        // XOR is commutative, so recombination succeeds the same way whichever share ends up in
        // the cookie and whichever ends up in the query parameter: swapping them still recovers
        // the same token.
        String[] shares = splitToken(token);

        webClient
                .get().uri("case/v1/cases?access_token_share=" + shares[1])
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[0])
                .exchange()
                .expectStatus().isOk();

        webClient
                .get().uri("case/v1/cases?access_token_share=" + shares[0])
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, shares[1])
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testAccessTokenQueryParamTakesPriorityOverAccessTokenShares() {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/v1/cases")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        // access_token (whole token, priority 2) is checked - and used - before the
        // AccessTokenShare/access_token_share pair (priority 3) is even looked at, so garbage in
        // the latter never gets in the way.
        webClient
                .get().uri("case/v1/cases?access_token=" + token)
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, "not-a-valid-share")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testAuthorizationHeaderTakesPriorityOverQueryAndShares() {
        initStubForJwk();

        stubFor(get(urlEqualTo("/v1/cases")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        // A garbage access_token and share cookie must be ignored when a valid Authorization
        // header is also present.
        webClient
                .get().uri("case/v1/cases?access_token=not-a-valid-token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .cookie(ACCESS_TOKEN_SHARE_COOKIE_NAME, "not-a-valid-share")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testAudienceValidation() {
        initStubForJwk();

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        // Test with token having valid audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        // Test with token having invalid audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithNotAllowedAudience)
                .exchange()
                .expectStatus().isUnauthorized();

        // Test with opaque token having valid audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "clientopaquetoken")
                .exchange()
                .expectStatus().isOk();

        // Test with opaque token having invalid audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "invalidAudienceOpaqueToken")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    private void stubUserRecordConnection() {
        // Stub for record-connection endpoint that handles both true and false values
        stubFor(head(urlPathMatching(String.format("/v1/users/%s/record-connection", "chmits")))
                .withQueryParam("isConnectionAccepted", matching("(true|false)"))
                .withPort(port)
                .willReturn(aResponse().withStatus(200)));
    }

    private void initStubForJwk() {
        stubUserRecordConnection();

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("{"
                        + "\"jwks_uri\": \"http://localhost:" + port + "/jwks\","
                                + "\"introspection_endpoint\": \"http://localhost:" + port + "/introspection\""
                        + "}")));

        stubFor(get(urlEqualTo("/jwks"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));

        // Introspection endpoint for valid opaque token
        stubFor(post(urlEqualTo("/introspection"))
                .withRequestBody(equalTo("client_id=gridsuite&client_secret=secret&token=clientopaquetoken"))
                .willReturn(aResponse()
                    .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .withBody("{\"active\":true,\"token_type\":\"Bearer\",\"exp\":2673442276,\"client_id\":\"chmits\"}")));

        // Introspection endpoint for invalid audience opaque token
        stubFor(post(urlEqualTo("/introspection"))
                .withRequestBody(equalTo("client_id=gridsuite&client_secret=secret&token=invalidAudienceOpaqueToken"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"active\":true,\"token_type\":\"Bearer\",\"exp\":2673442276,\"client_id\":\"unauthorized.app\"}")));
    }

    @Test
    void testClientIdFallback() {
        initStubForJwk();

        stubFor(get(urlEqualTo("/v1/cases"))
                .withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}]")));

        // Test with token having valid client_id but no audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithValidClientId)
                .exchange()
                .expectStatus().isUnauthorized();

        // Test with token having invalid client_id and no audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithInvalidClientId)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void testJwksUpdate() {
        stubUserRecordConnection();

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{"
                                + "\"jwks_uri\": \"http://localhost:" + port + "/jwks\","
                                + "\"introspection_endpoint\": \"http://localhost:" + port + "/introspection\""
                                + "}")));

        UUID stubId = UUID.randomUUID();

        stubFor(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"keys\" : [] }")));

        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        editStub(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();

        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token2)
                .exchange()
                .expectStatus().isUnauthorized();

        stubFor(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + ", " + rsaKey2.toJSONString() + "] }")));

        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token2)
                .exchange()
                .expectStatus().isOk();

        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void invalidToken() {
        stubUserRecordConnection();

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{"
                                + "\"jwks_uri\": \"http://localhost:" + port + "/jwks\","
                                + "\"introspection_endpoint\": \"http://localhost:" + port + "/introspection\""
                                + "}")));

        stubFor(post(urlEqualTo("/introspection"))
                .willReturn(aResponse()
                    .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .withBody("{\"active\":false}")));

        stubFor(get(urlEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));

        // test with no token
        webClient
                .get().uri("case/v1/cases")
                .exchange()
                .expectStatus().isUnauthorized();

        //test with an expired token
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + expiredToken)
                .exchange()
                .expectStatus().isUnauthorized();

        //test with with not allowed issuer
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithNotAllowedIssuer)
                .exchange()
                .expectStatus().isUnauthorized();

        String tokenWithFakeAlgorithm = token.replaceFirst("U", "Q");
        String tokenWithFakeAudience = token.replaceFirst("X", "L");

        //test with token with a fake algorithm
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithFakeAlgorithm)
                .exchange()
                .expectStatus().isUnauthorized();

        //test with token with fake audience
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenWithFakeAudience)
                .exchange()
                .expectStatus().isUnauthorized();

        // test with non JSON token, non valid reference token
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "NonValidToken")
                .exchange()
                .expectStatus().isUnauthorized();

        //test with a incorrect Authorization value
        webClient
                .get().uri("case/v1/cases")
                .header(HttpHeaders.AUTHORIZATION, token)
                .exchange()
                .expectStatus().isBadRequest();

        // test without a token
        WebSocketClient client = new StandardWebSocketClient();
        client.execute(URI.create("ws://localhost:" +
                this.localServerPort + "/study-notification/notify"),
            ws -> ws.receive().then()).doOnSuccess(s -> fail("Should have thrown"));
    }

    @TestConfiguration
    static class MyTestConfiguration {
        @Bean
        WireMockConfigurationCustomizer optionsCustomizer() {
            return new WireMockConfigurationCustomizer() {
                private static final String SEC_WEBSOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                @Override
                public void customize(WireMockConfiguration options) {
                    Helper<Object> secWebsocketAcceptHelper = (context, options1) -> {
                        String in = context.toString() + SEC_WEBSOCKET_MAGIC;
                        byte[] hashed;
                        try {
                            hashed = MessageDigest.getInstance("SHA-1").digest(in.getBytes(StandardCharsets.UTF_8));
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        }
                        return Base64.getEncoder().encodeToString(hashed);
                    };
                    options.extensions(
                            new ResponseTemplateTransformer(true, "sec-websocket-accept", secWebsocketAcceptHelper));
                }
            };
        }
    }
}
