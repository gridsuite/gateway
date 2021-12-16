/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "backing-services.directory-server.base-uri=http://localhost:${wiremock.server.port}",
        "backing-services.explore-server.base-uri=http://localhost:${wiremock.server.port}"
    }
)
@AutoConfigureWireMock(port = 0)
public class DirectoryAccessControlTest {

    @Value("${wiremock.server.port}")
    int port;

    @LocalServerPort
    private String localServerPort;

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

        stubFor(get(urlEqualTo("/v1/root_directories")).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("[{\"name\": \"test\"}]")));

        stubFor(get(urlEqualTo("/v1/root_directories")).withHeader("userId", equalTo("user2"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("[{\"name\": \"test\"}]")));

        webClient
            .get().uri("directory/v1/root_directories")
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].name").isEqualTo("test");

        webClient
            .get().uri("directory/v1/root_directories")
            .header("Authorization", "Bearer " + tokenUser2)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].name").isEqualTo("test");
    }

    @Test
    public void testWithForbiddenRequest() {
        initStubForJwk();

        System.out.println(String.format("LOCAL PORT : %s", localServerPort));
        System.out.println(String.format("PORT : %s", port));
        System.out.println(String.format("URI directory : %s", servicesURIsConfig.getDirectoryServerBaseUri()));

        UUID uuid = UUID.randomUUID();

        stubFor(head(urlEqualTo(String.format("/v1/elements?id=", uuid))).withHeader("userId", equalTo("user1"))
            .withPort(port)
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")));

        stubFor(get(urlEqualTo(String.format("/v1/directories/%s/elements", uuid))).withHeader("userId", equalTo("user1"))
            .willReturn(aResponse()
                .withHeader("Content-Type", "application/json")
                .withBody("[{\"name\": \"test\"}]")));

        webClient
            .get().uri(String.format("directory/v1/directories/%s/elements", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].name").isEqualTo("test");

        webClient
            .options().uri(String.format("directory/v1/directories/%s/elements", uuid))
            .header("Authorization", "Bearer " + tokenUser1)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].name").isEqualTo("test");
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
