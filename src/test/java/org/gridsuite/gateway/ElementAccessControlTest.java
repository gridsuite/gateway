/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.gridsuite.gateway.dto.AccessControlInfos;
import org.gridsuite.gateway.endpoints.ExploreServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "gridsuite.services.directory-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.explore-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.study-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.actions-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.filter-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.user-admin-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.sensitivity-analysis-server.base-uri=http://localhost:${wiremock.server.port}",
        "gridsuite.services.study-config-server.base-uri=http://localhost:${wiremock.server.port}",
        "allowed-audiences=test.app,chmits",
        "allowed-clients=chmits",
    }
)
@AutoConfigureWireMock(port = 0)
class ElementAccessControlTest {

    @Value("${wiremock.server.port}")
    private int port;

    @Autowired
    private WebTestClient webClient;

    private String tokenUser1;

    private String tokenUser2;

    private RSAKey rsaKey;

    @BeforeEach
    void prepareToken() throws JOSEException {
        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
            .keyID("123")
            .generate();

        rsaKey = rsaJWK.toPublicJWK();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Prepare JWT with claims set for user 'user1'
        JWTClaimsSet claimsSet1 = new JWTClaimsSet.Builder()
            .subject("user1")
            .audience("test.app")
            .issuer("http://localhost:" + port)
            .issueTime(new Date())
            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
            .build();

        // Prepare JWT with claims set for user 'user2'
        JWTClaimsSet claimsSet2 = new JWTClaimsSet.Builder()
            .subject("user2")
            .audience("test.app")
            .issuer("http://localhost:" + port)
            .issueTime(new Date())
            .expirationTime(new Date(new Date().getTime() + 60 * 1000))
            .build();

        SignedJWT signedJWT1 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet1);
        SignedJWT signedJWT2 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSet2);

        // Compute the RSA signature
        signedJWT1.sign(signer);
        signedJWT2.sign(signer);

        tokenUser1 = signedJWT1.serialize();
        tokenUser2 = signedJWT2.serialize();
    }

    @Test
    void testWithNoControl() {
        initStubForJwk();

        // No control for directory server (made inside the endpoint)
        stubFor(get(urlEqualTo("/v1/root_directories")).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        webClient
            .get().uri("directory/v1/root_directories")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        // No control for some study server root paths
        stubFor(get(urlEqualTo("/v1/search")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/svg-component-libraries")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/export-network-formats")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/loadflow-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/security-analysis-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/sensitivity-analysis-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/non-evacuated-energy-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/dynamic-simulation-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/dynamic-security-analysis-default-provider")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        webClient
            .get().uri("study/v1/search")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
            .get().uri("study/v1/svg-component-libraries")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
            .get().uri("study/v1/export-network-formats")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
            .get().uri("study/v1/loadflow-default-provider")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
                .get().uri("study/v1/security-analysis-default-provider")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
        webClient
                .get().uri("study/v1/sensitivity-analysis-default-provider")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
        webClient
            .get().uri("study/v1/non-evacuated-energy-default-provider")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
                .get().uri("study/v1/dynamic-simulation-default-provider")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
        webClient
                .get().uri("study/v1/dynamic-security-analysis-default-provider")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testGetElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/studies/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/studies/%s", uuid))).withHeader("userId", equalTo("user2"))
                .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/studies/metadata?ids=%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/studies/metadata?ids=%s", uuid))).withHeader("userId", equalTo("user2"))
                .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/spreadsheet-configs/%s", uuid))).withHeader("userId", equalTo("user1"))
                .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/spreadsheet-config-collections/%s", uuid))).withHeader("userId", equalTo("user1"))
                .willReturn(aResponse()));

        webClient
                .get().uri(String.format("study-config/v1/spreadsheet-configs/%s", uuid))
                .header("Authorization", "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();

        webClient
                .get().uri(String.format("study-config/v1/spreadsheet-config-collections/%s", uuid))
                .header("Authorization", "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();

        webClient
                .get().uri(String.format("study-config/v1/spreadsheet-configs/%s", uuid))
                .header("Authorization", "Bearer " + tokenUser2)
                .exchange()
                .expectStatus().isNotFound();

        webClient
                .get().uri(String.format("study-config/v1/spreadsheet-config-collections/%s", uuid))
                .header("Authorization", "Bearer " + tokenUser2)
                .exchange()
                .expectStatus().isNotFound();

        webClient
                .get().uri("study-config/v1/spreadsheet-configs/invalid-uuid")
                .header("Authorization", "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isNotFound();

        webClient
                .get().uri("study-config/v1/spreadsheet-config-collections/invalid-uuid")
                .header("Authorization", "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isNotFound();

        webClient
            .get().uri("study/v1/studies")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        // Bad uuid
        webClient
            .get().uri(String.format("study/v1/studies/%s", "badUuid"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .get().uri(String.format("study/v1/studies/%s", (UUID) null))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .get().uri(String.format("study/v1/studies/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("study/v1/studies/metadata?ids=%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("filter/v1/filters/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("study/v1/studies/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("study/v1/studies/metadata?ids=%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .get().uri(String.format("filter/v1/filters/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isNotFound();
    }

    @Test
    void testCreateElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/directories?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 is also allowed
        stubFor(head(urlEqualTo(String.format("/v1/directories?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()));
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/script-contingency-lists?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/filters?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Direct creation of elements without going through the explore server
        webClient
            .post().uri("study/v1/studies")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .post().uri("actions/v1/script-contingency-lists")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .post().uri("filter/v1/filters")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        // Creation of elements without directory parent
        webClient
            .post().uri(String.format("explore/v1/explore/studies"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        // Creation of elements with bad parameter for directory parent uuid
        webClient
            .post().uri(String.format("explore/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID + "bad", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        // Creation of elements with bad directory parent uuid
        webClient
            .post().uri(String.format("explore/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, "badUuid"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .post().uri(String.format("explore/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, null))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        // Creation of elements with multiple directory parent uuids
        webClient
            .post().uri(String.format("explore/v1/explore/studies?%s=%s,%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid, uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .post().uri(String.format("explore/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .post().uri(String.format("explore/v1/explore/script-contingency-lists?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .post().uri(String.format("explore/v1/explore/filters?%s=%s", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

    }

    @Test
    void testCreateSubElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/studies/%s/tree/nodes", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        webClient
            .post().uri("study/v1/studies")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .post().uri(String.format("study/v1/studies/%s/tree/nodes", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    void testUpdateElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()));

        stubFor(put(urlEqualTo(String.format("/v1/studies/%s/nodes/idNode", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(put(urlEqualTo(String.format("/v1/script-contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(put(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Put with no or bad uuid
        webClient
            .put().uri("study/v1/studies/nodes/idNode")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", (UUID) null))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", "badUuid"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .put().uri(String.format("actions/v1/script-contingency-lists/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .put().uri(String.format("filter/v1/filters/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    void testDeleteElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/explore/elements/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/studies/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Delete elements with no or bad uuid
        webClient
            .delete().uri("explore/v1/explore/elements")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", (UUID) null))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();
        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", "badUuid"))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isNotFound();

        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("study/v1/studies/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("filter/v1/filters/%s", uuid))
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    void testSupervisionEndpointsAccess() {
        initStubForJwk();

        // Test access to a supervision endpoint (should be forbidden)
        webClient.get().uri("study/v1/supervision/studies")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Test access to an endpoint containing 'supervision' but not matching the blocked pattern
        // This should pass through the filter
        stubFor(get(urlEqualTo("/v1/studies/supervision-report"))
                .withHeader("userId", equalTo("user1"))
                .willReturn(aResponse().withStatus(200)));

        webClient.get().uri("study/v1/studies/supervision-report")
                .header("Authorization", "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void testAccessControlInfos() {
        List<UUID> emptyList = List.of();
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> AccessControlInfos.create(emptyList));
        assertEquals("List of elements is empty", exception.getMessage());
    }

    private void initStubForJwk() {
        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "user1"))).withPort(port)
                .willReturn(aResponse().withStatus(200)));

        stubFor(head(urlEqualTo(String.format("/v1/users/%s", "user2"))).withPort(port)
                .willReturn(aResponse().withStatus(200)));

        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("{\"jwks_uri\": \"http://localhost:" + port + "/jwks\"}")));

        stubFor(get(urlEqualTo("/jwks"))
            .willReturn(aResponse()
                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));
    }

    @Test
    void testDuplicateElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/directories?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
                .willReturn(aResponse()));
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
                .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_DUPLICATE_FROM_ID, uuid))).withHeader("userId", equalTo("user1"))
                .willReturn(aResponse()));

        // Direct creation of elements without going through the explor server is forbidden
        webClient
                .post().uri("study/v1/studies")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isNotFound();

        webClient
                .post().uri(String.format("explore/v1/explore/studies?%s=%s", ExploreServer.QUERY_PARAM_DUPLICATE_FROM_ID, uuid))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenUser1)
                .exchange()
                .expectStatus().isOk();
    }
}
