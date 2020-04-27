package org.gridsuite.gateway;

import com.nimbusds.jose.*;
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
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"caseServerBaseUri=http://localhost:${wiremock.server.port}", "studyServerBaseUri=http://localhost:${wiremock.server.port}"})
@AutoConfigureWireMock(port = 0)
public class TokenValidationTest {

    @Value("${wiremock.server.port}")
    int port;

    private String token;

    private String expiredToken;

    private String tokenWithNotAllowedissuer;

    private RSAKey rsaKey;

    @Autowired
    WebTestClient webClient;

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
        SignedJWT signedJWTExpired = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForExpiredToken);
        SignedJWT signedJWTWithIssuerNotAllowed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(), claimsSetForTokenWithIssuerNotAllowed);

        // Compute the RSA signature
        signedJWT.sign(signer);
        signedJWTExpired.sign(signer);
        signedJWTWithIssuerNotAllowed.sign(signer);

        token = signedJWT.serialize();
        expiredToken = signedJWTExpired.serialize();
        tokenWithNotAllowedissuer = signedJWTWithIssuerNotAllowed.serialize();
    }

    @Test
    public void gatewayTest() throws Exception {
        stubFor(get(urlEqualTo("/v1/studies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"studyName\": \"CgmesStudy\", \"caseFormat\" :\"CGMES\"}, {\"studyName\": \"IIDMStudy\", \"caseFormat\" :\"IIDM\"}]")));

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
                .get().uri("study/v1/studies")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].caseFormat").isEqualTo("CGMES")
                .jsonPath("$[1].caseFormat").isEqualTo("IIDM")
                .jsonPath("$[0].studyName").isEqualTo("CgmesStudy")
                .jsonPath("$[1].studyName").isEqualTo("IIDMStudy");

    }

    @Test
    public void invalidToken() throws Exception {

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

        //test with non JSON token
        webClient
                .get().uri("case/v1/cases")
                .header("Authorization", "Bearer" + token)
                .exchange()
                .expectStatus().isEqualTo(400);

    }
}
