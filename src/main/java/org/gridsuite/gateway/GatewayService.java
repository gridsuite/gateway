package org.gridsuite.gateway;

import org.gridsuite.gateway.dto.OpenIdConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Objects;

@Service
public class GatewayService {
    private RestTemplate issRest;

    public GatewayService() {
        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();
        issRest = restTemplateBuilder.build();
    }

    String getJwksUrl(String issBaseUri) {
        issRest.setUriTemplateHandler(new DefaultUriBuilderFactory(issBaseUri));

        String path = UriComponentsBuilder.fromPath("/.well-known/openid-configuration")
                .toUriString();

        ResponseEntity<OpenIdConfiguration> responseEntity = issRest.exchange(path,
                HttpMethod.GET,
                HttpEntity.EMPTY,
                OpenIdConfiguration.class);

        return Objects.requireNonNull(responseEntity.getBody()).getJwks_uri();
    }
}
