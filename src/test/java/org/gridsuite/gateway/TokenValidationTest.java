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
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.cloud.contract.wiremock.WireMockConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.socket.client.StandardWebSocketClient;
import org.springframework.web.reactive.socket.client.WebSocketClient;
import reactor.core.publisher.Mono;
import wiremock.com.github.jknack.handlebars.Helper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"powsybl.services.case-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.study-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.merge-orchestrator-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.merge-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.directory-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.actions-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.study-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.config-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.config-notification-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.directory-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.explore-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.cgmes-boundary-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.dynamic-mapping-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.filter-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.report-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.network-modification-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.user-admin-server.base-uri=http://localhost:${wiremock.server.port}",
        "grisuite.services.sensitivity-analysis-server.base-uri=http://localhost:${wiremock.server.port}",
    })

@AutoConfigureWireMock(port = 0)
public class TokenValidationTest {

    @Value("${wiremock.server.port}")
    int port;

    @LocalServerPort
    private String localServerPort;

    private String token;

    private String token2;

    private String expiredToken;

    private String tokenWithNotAllowedissuer;

    private RSAKey rsaKey;

    private RSAKey rsaKey2;

    @Autowired
    WebTestClient webClient;

    @Before
    public void prepareToken() throws JOSEException {
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

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet);
        SignedJWT signedJWT2 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK2.getKeyID()).build(), claimsSet);
        SignedJWT signedJWTExpired = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForExpiredToken);
        SignedJWT signedJWTWithIssuerNotAllowed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForTokenWithIssuerNotAllowed);

        // Compute the RSA signature
        signedJWT.sign(signer);
        signedJWT2.sign(signer2);
        signedJWTExpired.sign(signer);
        signedJWTWithIssuerNotAllowed.sign(signer);

        token = signedJWT.serialize();
        token2 = signedJWT2.serialize();
        expiredToken = signedJWTExpired.serialize();
        tokenWithNotAllowedissuer = signedJWTWithIssuerNotAllowed.serialize();
    }

    private void testWebsocket(String name) throws InterruptedException {
        //Test a websocket with token in query parameters
        WebSocketClient client = new StandardWebSocketClient();
        HttpHeaders headers = new HttpHeaders();
        Mono<Void> wsconnection = client.execute(
            URI.create("ws://localhost:" + this.localServerPort + "/" + name + "/notify?access_token=" + token), headers,
            ws -> ws.receive().then());
        wsconnection.subscribe();

        // Busy loop waiting to check that spring-gateway contacted our wiremock server
        // Is there a better way to wait for wiremock to complete the request ?
        boolean done = false;
        for (int i = 0; i < 100; i++) {
            Thread.sleep(10);
            try {
                verify(getRequestedFor(urlPathEqualTo("/notify"))
                        .withHeader("Connection", equalTo("Upgrade"))
                        .withHeader("Upgrade", equalTo("websocket")));
                done = true;
            } catch (VerificationException e) {
                // nothing to do
            }
            if (done) {
                break;
            }
        }
        if (!done) {
            Assert.fail("Wiremock didn't receive the websocket connection");
        }
        try {
            wsconnection.timeout(Duration.ofMillis(100)).block();
            Assert.fail("websocket client was closed but should remain open");
        } catch (Exception ignored) {
            //should timeout
        }
    }

    @Test
    public void gatewayTest() {
        initStubForJwk();

        UUID elementUuid = UUID.randomUUID();

        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", elementUuid))).withPort(port).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/explore/elements/metadata?ids=%s", elementUuid))).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(String.format("[{\"elementUuid\" : \"%s\", \"type\" : \"STUDY\", \"subdirectoriesCount\" : \"0\", \"specificMetadata\" : {\"id\" : \"%s\", \"caseFormat\" : \"IIDM\"}}]", elementUuid, elementUuid))));

        stubFor(get(urlEqualTo(String.format("/v1/studies/metadata?ids=%s", elementUuid))).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format("[{\"id\" : \"%s\", \"caseFormat\" : \"IIDM\"}]", elementUuid))));

        stubFor(get(urlEqualTo(String.format("/v1/contingency-lists/metadata?ids=%s", elementUuid))).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format("[{\"id\" : \"%s\", \"type\" : \"SCRIPT\"}]", elementUuid))));

        stubFor(get(urlEqualTo(String.format("/v1/filters/metadata?ids=%s", elementUuid))).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody(String.format("[{\"id\": \"%s\", \"type\" :\"LINE\"}]", elementUuid))));

        stubFor(get(urlEqualTo("/v1/root_directories")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"test\"}]")));

        stubFor(get(urlEqualTo("/v1/cases")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlEqualTo("/v1/parameters")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"theme\": \"dark\"}]")));

        stubFor(get(urlEqualTo("/v1/configs")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"process\": \"TEST\", \"tsos\" : [\"BE\", \"NL\"]}]")));

        stubFor(get(urlEqualTo("/v1/boundaries")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("[{\"name\": \"boundary1\", \"id\" :\"da47a173-22d2-47e8-8a84-aa66e2d0fafb\"}]")));

        stubFor(get(urlEqualTo("/mappings")).withHeader("userId", equalTo("chmits"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"mapping1\", \"rules\":[]}]")));

        stubFor(get(urlEqualTo("/v1/reports")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"id\": \"report1\", \"reports\" :[{\"date\":\"2001:01:01T11:11\", \"report\": \"Lets Rock\" }]}")));

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("testCase")
                .jsonPath("$[1].name").isEqualTo("testCase2")
                .jsonPath("$[0].format").isEqualTo("XIIDM")
                .jsonPath("$[1].format").isEqualTo("CGMES");

        webClient
                .get().uri("study/v1/studies/metadata?ids=" + elementUuid)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
                .jsonPath("$[0].caseFormat").isEqualTo("IIDM");

        webClient
                .get().uri("merge/v1/configs")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].process").isEqualTo("TEST")
                .jsonPath("$[0].tsos[0]").isEqualTo("BE")
                .jsonPath("$[0].tsos[1]").isEqualTo("NL");

        webClient
                .get().uri("actions/v1/contingency-lists/metadata?ids=" + elementUuid)
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
                .jsonPath("$[0].type").isEqualTo("SCRIPT");

        webClient
                .get().uri("config/v1/parameters")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].theme").isEqualTo("dark");

        webClient
                .get().uri("directory/v1/root_directories")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("test");

        webClient
            .get().uri("boundary/v1/boundaries")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].name").isEqualTo("boundary1")
            .jsonPath("$[0].id").isEqualTo("da47a173-22d2-47e8-8a84-aa66e2d0fafb");

        webClient
                .get().uri("dynamic-mapping/mappings")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("mapping1");

        webClient
            .get().uri("filter/v1/filters/metadata?ids=" + elementUuid)
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].id").isEqualTo(elementUuid.toString())
            .jsonPath("$[0].type").isEqualTo("LINE");

        webClient
            .get().uri("report/v1/reports")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.id").isEqualTo("report1")
            .jsonPath("$.reports[0].report").isEqualTo("Lets Rock")
            .jsonPath("$.reports[0].date").isEqualTo("2001:01:01T11:11");

        webClient
            .get().uri("explore/v1/explore/elements/metadata?ids=" + elementUuid)
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].elementUuid").isEqualTo(elementUuid.toString())
            .jsonPath("$[0].type").isEqualTo("STUDY")
            .jsonPath("$[0].subdirectoriesCount").isEqualTo(0);
    }

    @Test
    @SneakyThrows
    public void testWebsockets() {
        initStubForJwk();

        stubFor(get(urlPathEqualTo("/notify")).withHeader("userId", equalTo("chmits"))
            .willReturn(aResponse()
                .withHeader("Sec-WebSocket-Accept", "{{{sec-websocket-accept request.headers.Sec-WebSocket-Key}}}")
                .withHeader("Upgrade", "websocket")
                .withHeader("Connection", "Upgrade")
                .withStatus(101)
                .withStatusMessage("Switching Protocols")));

        testWebsocket("study-notification");
        testWebsocket("config-notification");
        testWebsocket("merge-notification");
        testWebsocket("directory-notification");
    }

    private void initStubForJwk() {
        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "chmits"))).withPort(port)
                .willReturn(aResponse().withStatus(200)));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"jwks_uri\": \"http://localhost:" + port + "/jwks\"}")));

        stubFor(get(urlEqualTo("/jwks"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));
    }

    @Test
    public void testJwksUpdate() {
        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "chmits"))).withPort(port)
                .willReturn(aResponse().withStatus(200)));

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"jwks_uri\": \"http://localhost:" + port + "/jwks\"}")));

        UUID stubId = UUID.randomUUID();

        stubFor(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\" : [] }")));

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(401);

        editStub(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(200);

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token2)
                .exchange()
                .expectStatus().isEqualTo(401);

        stubFor(get(urlEqualTo("/jwks"))
                .withId(stubId)
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + ", " + rsaKey2.toJSONString() + "] }")));

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token2)
                .exchange()
                .expectStatus().isEqualTo(200);

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(200);
    }

    @Test
    public void invalidToken() {
        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "chmits"))).withPort(port)
                .willReturn(aResponse().withStatus(200)));

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"jwks_uri\": \"http://localhost:" + port + "/jwks\"}")));

        stubFor(get(urlEqualTo("/jwks"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));

        // test with no token
        webClient
                .get().uri("case/v1/cases")
                .exchange()
                .expectStatus().isEqualTo(401);

        //test with an expired token
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + expiredToken)
                .exchange()
                .expectStatus().isEqualTo(401);

        //test with with not allowed issuer
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + tokenWithNotAllowedissuer)
                .exchange()
                .expectStatus().isEqualTo(401);

        String tokenWithFakeAlgorithm = token.replaceFirst("U", "Q");
        String tokenWithFakeAudience = token.replaceFirst("X", "L");

        //test with token with a fake algorithm
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + tokenWithFakeAlgorithm)
                .exchange()
                .expectStatus().isEqualTo(401);

        //test with token with fake audience
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + tokenWithFakeAudience)
                .exchange()
                .expectStatus().isEqualTo(401);

        //test with non JSON token
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + "NonValidToken")
                .exchange()
                .expectStatus().isEqualTo(401);

        //test with a incorrect Authorization value
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", token)
                .exchange()
                .expectStatus().isEqualTo(400);

        // test without a token
        WebSocketClient client = new StandardWebSocketClient();
        client.execute(URI.create("ws://localhost:" +
                this.localServerPort + "/study-notification/notify"),
            ws -> ws.receive().then()).doOnSuccess(s -> Assert.fail("Should have thrown"));
    }

    @Test
    public void forbiddenUserTest() {
        initStubForJwk();
        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "chmits"))).withPort(port)
                .willReturn(aResponse().withStatus(204)));

        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(403);
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
