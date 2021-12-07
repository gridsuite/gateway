package org.gridsuite.gateway;

import org.gridsuite.gateway.dto.OpenIdConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

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

        return Objects.requireNonNull(responseEntity.getBody()).getJwksUri();
    }

    static Mono<Void> completeWithCode(ServerWebExchange exchange, HttpStatus code) {
        exchange.getResponse().setStatusCode(code);
        if ("websocket".equalsIgnoreCase(exchange.getRequest().getHeaders().getUpgrade())) {
            // Force the connection to close for websockets handshakes to workaround apache
            // httpd reusing the connection for all subsequent requests in this connection.
            exchange.getResponse().getHeaders().set(HttpHeaders.CONNECTION, "close");
        }
        return exchange.getResponse().setComplete();
    }
}
