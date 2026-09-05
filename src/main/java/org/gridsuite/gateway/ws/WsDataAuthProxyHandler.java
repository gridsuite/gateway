/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.ws;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.CloseStatus;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import org.springframework.web.reactive.socket.client.ReactorNettyWebSocketClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * WebSocket proxy implementing "first-message authentication" to work around the browser
 * limitation of not being able to set an {@code Authorization} header on WebSocket connections.
 *
 * <p>Behavior:</p>
 * <ol>
 *   <li>Accepts the client WebSocket on {@code /ws-dataauth/**}.</li>
 *   <li>Reads the FIRST text frame and treats it as an opaque bearer token (no validation).
 *       The frame is consumed and never forwarded upstream. A timeout and size limit apply.</li>
 *   <li>Dials a NEW WebSocket to {@code ws://localhost:<upstream-port>} with the
 *       {@code /ws-dataauth} prefix stripped ({@code /ws-dataauth/foo/bar?x=y} →
 *       {@code /foo/bar?x=y}), setting {@code Authorization: Bearer <token>} on the handshake.</li>
 *   <li>Transparently relays all subsequent frames bidirectionally, preserving frame type.</li>
 *   <li>Propagates upstream handshake failures and close statuses to the client.</li>
 * </ol>
 *
 * @author Jon Harper <jon.harper at rte-france.com>
 */
@Component
public class WsDataAuthProxyHandler implements WebSocketHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(WsDataAuthProxyHandler.class);

    private static final Pattern PRINTABLE_ASCII = Pattern.compile("[\\x20-\\x7E]+");

    private static final int MAX_CLOSE_REASON_BYTES = 123;

    private final WsDataAuthProperties properties;

    private final ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();

    public WsDataAuthProxyHandler(WsDataAuthProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<Void> handle(WebSocketSession clientSession) {
        return clientSession.receive()
            .next() // frame #1: the token — consumed here, never forwarded upstream
            .timeout(properties.getAuthTimeout())
            .flatMap(frame -> proxy(clientSession, frame.getPayloadAsText()))
            .onErrorResume(TimeoutException.class,
                e -> clientSession.close(new CloseStatus(1008, "auth timeout")))
            .onErrorResume(e -> {
                LOGGER.debug("ws-dataauth client session error", e);
                return clientSession.close(new CloseStatus(1011, truncateReason("proxy error: " + e.getMessage())));
            });
    }

    private Mono<Void> proxy(WebSocketSession clientSession, String token) {
        if (token.isEmpty() || token.getBytes(StandardCharsets.UTF_8).length > properties.getMaxTokenBytes()
                || !PRINTABLE_ASCII.matcher(token).matches()) {
            // reject empty/oversized tokens and any characters outside printable ASCII
            // to prevent HTTP header injection on the upstream handshake
            return clientSession.close(new CloseStatus(1008, "invalid token frame"));
        }

        URI upstreamUri;
        try {
            upstreamUri = buildUpstreamUri(clientSession.getHandshakeInfo().getUri());
        } catch (URISyntaxException e) {
            return clientSession.close(new CloseStatus(1008, "invalid path"));
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token); // verbatim copy of frame #1, no validation by design

        LOGGER.debug("ws-dataauth proxying to {}", upstreamUri);

        return client.execute(upstreamUri, headers, upstreamSession ->
                Mono.zip(
                    upstreamSession.send(retained(clientSession.receive())),
                    clientSession.send(retained(upstreamSession.receive()))
                ).then())
            .onErrorResume(e -> {
                LOGGER.debug("ws-dataauth upstream failure for {}", upstreamUri, e);
                return clientSession.close(new CloseStatus(1008,
                        truncateReason("upstream rejected/failed: " + e.getMessage())));
            });
    }

    /**
     * Retains relayed frame payloads so they survive until the outbound write completes, and
     * releases any frame discarded on cancellation (e.g. when {@code Mono.zip} cancels one relay
     * direction because the other terminated) to avoid leaking pooled Netty buffers.
     */
    private static Flux<WebSocketMessage> retained(Flux<WebSocketMessage> in) {
        return in.map(f -> new WebSocketMessage(f.getType(), f.getPayload().retain()))
                 .doOnDiscard(WebSocketMessage.class, m -> DataBufferUtils.release(m.getPayload()));
    }

    /**
     * Maps {@code /ws-dataauth/foo/bar?x=y} to {@code ws://localhost:<upstream-port>/foo/bar?x=y}.
     */
    private URI buildUpstreamUri(URI clientUri) throws URISyntaxException {
        String path = clientUri.getRawPath();
        String stripped = path.startsWith(WsDataAuthProperties.PATH_PREFIX)
                ? path.substring(WsDataAuthProperties.PATH_PREFIX.length())
                : path;
        if (stripped.isEmpty()) {
            stripped = "/";
        }
        String query = clientUri.getRawQuery();
        return new URI("ws", null, "localhost", properties.getUpstreamPort(),
                stripped, null, null).resolve(query != null ? stripped + "?" + query : stripped)
            .isAbsolute()
                ? new URI("ws://localhost:" + properties.getUpstreamPort() + stripped + (query != null ? "?" + query : ""))
                : new URI("ws://localhost:" + properties.getUpstreamPort() + stripped + (query != null ? "?" + query : ""));
    }

    private static String truncateReason(String reason) {
        byte[] bytes = reason.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_CLOSE_REASON_BYTES) {
            return reason;
        }
        return new String(bytes, 0, MAX_CLOSE_REASON_BYTES, StandardCharsets.UTF_8);
    }
}
