/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.ws;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the /ws-dataauth first-frame authentication proxy.
 *
 * @author Jon Harper <jon.harper at rte-france.com>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"ws-dataauth.auth-timeout=2s"})
class WsDataAuthProxyTest {

    private static DisposableServer upstream;

    private static final List<String> UPSTREAM_AUTH_HEADERS = new CopyOnWriteArrayList<>();
    private static final List<String> UPSTREAM_PATHS = new CopyOnWriteArrayList<>();
    private static final ConcurrentLinkedQueue<String> UPSTREAM_RECEIVED = new ConcurrentLinkedQueue<>();

    @LocalServerPort
    private int gatewayPort;

    @BeforeAll
    static void startUpstream() {
        upstream = HttpServer.create()
            .host("localhost")
            .port(0)
            .route(routes -> routes.route(request -> request.uri().startsWith("/foo/bar"), (request, response) -> {
                UPSTREAM_AUTH_HEADERS.add(request.requestHeaders().get(HttpHeaders.AUTHORIZATION));
                UPSTREAM_PATHS.add(request.uri());
                return response.sendWebsocket((in, out) -> out.sendString(in.receive().asString()
                    .doOnNext(UPSTREAM_RECEIVED::add)
                    .map(s -> "echo:" + s)));
            }))
            .bindNow();
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @DynamicPropertySource
    static void wsProps(DynamicPropertyRegistry registry) {
        registry.add("ws-dataauth.upstream-port", () -> upstream.port());
    }

    @Test
    void tokenIsCopiedToAuthorizationHeaderAndNotForwarded() {
        ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();
        List<String> received = new CopyOnWriteArrayList<>();

        client.execute(URI.create("ws://localhost:" + gatewayPort + "/ws-dataauth/foo/bar?x=y"),
            session -> {
                Mono<Void> send = session.send(Flux.just(
                        session.textMessage("my-secret-token"),   // frame #1: token
                        session.textMessage("hello")));            // frame #2: payload
                Mono<Void> receive = session.receive()
                        .map(WebSocketMessage::getPayloadAsText)
                        .doOnNext(received::add)
                        .take(1)
                        .then();
                return send.and(receive);
            })
            .block(Duration.ofSeconds(10));

        assertThat(UPSTREAM_AUTH_HEADERS).contains("Bearer my-secret-token");
        assertThat(UPSTREAM_PATHS).contains("/foo/bar?x=y");
        assertThat(UPSTREAM_RECEIVED).contains("hello");
        assertThat(UPSTREAM_RECEIVED).doesNotContain("my-secret-token");
        assertThat(received).containsExactly("echo:hello");
    }

    @Test
    void invalidTokenIsRejected() {
        ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();

        client.execute(URI.create("ws://localhost:" + gatewayPort + "/ws-dataauth/foo/bar"),
            session -> session.send(Flux.just(session.textMessage("bad\r\ntoken")))
                .then(session.closeStatus()
                    .doOnNext(status -> assertThat(status.getCode()).isEqualTo(1008))
                    .then()))
            .block(Duration.ofSeconds(10));
    }

    @Test
    void authTimeoutClosesConnection() {
        ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();

        client.execute(URI.create("ws://localhost:" + gatewayPort + "/ws-dataauth/foo/bar"),
            session -> session.closeStatus()
                .doOnNext(status -> assertThat(status.getCode()).isEqualTo(1008))
                .then())
            .block(Duration.ofSeconds(10));
    }

    @Test
    void unknownUpstreamPathClosesWithUpstreamError() {
        ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();

        client.execute(URI.create("ws://localhost:" + gatewayPort + "/ws-dataauth/does/not/exist"),
            session -> session.send(Flux.just(session.textMessage("tok")))
                .then(session.closeStatus()
                    .doOnNext(status -> assertThat(status.getCode()).isEqualTo(1008))
                    .then()))
            .block(Duration.ofSeconds(10));
    }
}
