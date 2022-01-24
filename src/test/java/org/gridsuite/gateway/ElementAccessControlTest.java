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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "backing-services.directory-server.base-uri=http://localhost:${wiremock.server.port}",
        "backing-services.explore-server.base-uri=http://localhost:${wiremock.server.port}",
        "backing-services.study-server.base-uri=http://localhost:${wiremock.server.port}",
        "backing-services.actions-server.base-uri=http://localhost:${wiremock.server.port}",
        "backing-services.filter-server.base-uri=http://localhost:${wiremock.server.port}",
    }
)
@AutoConfigureWireMock(port = 0)
public class ElementAccessControlTest {

    @Value("${wiremock.server.port}")
    int port;

    @Autowired
    WebTestClient webClient;

    @Autowired
    ServiceURIsConfig servicesURIsConfig;

    private String tokenUser1;

    private String tokenUser2;

    private RSAKey rsaKey;

    @Before
    public void prepareToken() throws JOSEException {
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
    public void testWithNoControl() {
        initStubForJwk();

        // No control for directory server (made inside the endpoint)
        stubFor(get(urlEqualTo("/v1/root_directories")).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        webClient
            .get().uri("directory/v1/root_directories")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        // No control for some study server root paths
        stubFor(get(urlEqualTo("/v1/search")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/svg-component-libraries")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        stubFor(get(urlEqualTo("/v1/export-network-formats")).withHeader("userId", equalTo("user1")).willReturn(aResponse()));
        webClient
            .get().uri("study/v1/search")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
            .get().uri("study/v1/svg-component-libraries")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
        webClient
            .get().uri("study/v1/export-network-formats")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    public void testGetElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 not allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse().withStatus(HttpStatus.FORBIDDEN.value())));

        stubFor(get(urlEqualTo(String.format("/v1/studies/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/studies/metadata?ids=%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(get(urlEqualTo(String.format("/v1/contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // No uuid element forbidden
        webClient
            .get().uri("study/v1/studies")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Bad uuid forbidden
        webClient
            .get().uri(String.format("study/v1/studies/%s", "badUuid"))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .get().uri(String.format("study/v1/studies/%s", (UUID) null))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .get().uri(String.format("study/v1/studies/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("study/v1/studies/metadata?ids=%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("filter/v1/filters/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .get().uri(String.format("study/v1/studies/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .get().uri(String.format("study/v1/studies/metadata?ids=%s", uuid))
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .get().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .get().uri(String.format("filter/v1/filters/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isForbidden();
    }

    @Test
    public void testCreateElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/directories?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 not allowed
        stubFor(head(urlEqualTo(String.format("/v1/directories?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse().withStatus(HttpStatus.FORBIDDEN.value())));
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse().withStatus(HttpStatus.FORBIDDEN.value())));

        stubFor(post(urlEqualTo(String.format("/v1/explore/studies/%s?%s=%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/script-contingency-lists/%s?%s=%s", "scl1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/explore/filters/%s?%s=%s", "filter1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Direct creation of elements without going through the explor server is forbidden
        webClient
            .post().uri("study/v1/studies")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .post().uri("actions/v1/script-contingency-lists")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .post().uri("filter/v1/filters")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Creation of elements without directory parent is forbidden
        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s", "study1"))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Creation of elements with bad parameter for directory parent uuid is forbidden
        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s?%s=%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID + "bad", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Creation of elements with bad directory parent uuid is forbidden
        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s?%s=%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, "badUuid"))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s?%s=%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, null))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        // Creation of elements with multiple directory parent uuids is forbidden
        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s?%s=%s,%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid, uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .post().uri(String.format("explore/v1/explore/studies/%s?%s=%s", "study1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .post().uri(String.format("explore/v1/explore/script-contingency-lists/%s?%s=%s", "scl1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .post().uri(String.format("explore/v1/explore/filters/%s?%s=%s", "filter1", ExploreServer.QUERY_PARAM_PARENT_DIRECTORY_ID, uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

    }

    @Test
    public void testCreateSubElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(post(urlEqualTo(String.format("/v1/studies/%s/tree/nodes", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        webClient
            .post().uri("study/v1/studies")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .post().uri(String.format("study/v1/studies/%s/tree/nodes", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    public void testUpdateElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 not allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse().withStatus(HttpStatus.FORBIDDEN.value())));

        stubFor(put(urlEqualTo(String.format("/v1/studies/%s/nodes/idNode", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(put(urlEqualTo(String.format("/v1/script-contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(put(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Put with no or bad uuid is forbidden
        webClient
            .put().uri("study/v1/studies/nodes/idNode")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", (UUID) null))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", "badUuid"))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .put().uri(String.format("study/v1/studies/%s/nodes/idNode", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .put().uri(String.format("actions/v1/script-contingency-lists/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .put().uri(String.format("filter/v1/filters/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    public void testDeleteElements() {
        initStubForJwk();

        UUID uuid = UUID.randomUUID();

        // user1 allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // user2 not allowed
        stubFor(head(urlEqualTo(String.format("/v1/elements?ids=%s", uuid))).withPort(port).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse().withStatus(HttpStatus.FORBIDDEN.value())));

        stubFor(delete(urlEqualTo(String.format("/v1/explore/elements/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/studies/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/contingency-lists/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        stubFor(delete(urlEqualTo(String.format("/v1/filters/%s", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()));

        // Delete elements with no or bad uuid is forbidden
        webClient
            .delete().uri("explore/v1/explore/elements")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", (UUID) null))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();
        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", "badUuid"))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isForbidden();

        webClient
            .delete().uri(String.format("explore/v1/explore/elements/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("study/v1/studies/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("actions/v1/contingency-lists/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();

        webClient
            .delete().uri(String.format("filter/v1/filters/%s", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    public void testAccessControlInfos() {
        List<UUID> emptyList = List.of();

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> AccessControlInfos.createDirectoryType(emptyList));
        assertEquals("List of directories is empty", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> AccessControlInfos.createElementType(emptyList));
        assertEquals("List of elements is empty", exception.getMessage());
    }

    private void initStubForJwk() {
        stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"jwks_uri\": \"http://localhost:" + port + "/jwks\"}")));

        stubFor(get(urlEqualTo("/jwks"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("{\"keys\" : [ " + rsaKey.toJSONString() + " ] }")));
    }
}
