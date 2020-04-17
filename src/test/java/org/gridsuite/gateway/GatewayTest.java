package org.gridsuite.gateway;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"caseServerBaseUri=http://localhost:${wiremock.server.port}", "studyServerBaseUri=http://localhost:${wiremock.server.port}", "ignoreTokenValidation=true"})
@AutoConfigureWireMock(port = 0)
public class GatewayTest {

    @Autowired
    WebTestClient webClient;

    @Test
    public void contextLoads() throws Exception {
        stubFor(get(urlEqualTo("/v1/studies"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"studyName\": \"CgmesStudy\", \"caseFormat\" :\"CGMES\"}, {\"studyName\": \"IIDMStudy\", \"caseFormat\" :\"IIDM\"}]")));

        stubFor(get(urlEqualTo("/v1/cases"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("[{\"name\": \"testCase\", \"format\" :\"XIIDM\"}, {\"name\": \"testCase2\", \"format\" :\"CGMES\"}]")));

        webClient
                .get().uri("case/v1/cases")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[0].name").isEqualTo("testCase")
                .jsonPath("$[1].name").isEqualTo("testCase2")
                .jsonPath("$[0].format").isEqualTo("XIIDM")
                .jsonPath("$[1].format").isEqualTo("CGMES");

        webClient
                .get().uri("study/v1/studies")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                //.consumeWith()
                .jsonPath("$[0].caseFormat").isEqualTo("CGMES")
                .jsonPath("$[1].caseFormat").isEqualTo("IIDM")
                .jsonPath("$[0].studyName").isEqualTo("CgmesStudy")
                .jsonPath("$[1].studyName").isEqualTo("IIDMStudy");
    }
}
