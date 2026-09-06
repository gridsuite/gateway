/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.ws;

import io.netty.handler.codec.http.websocketx.WebSocketClientHandshakeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.context.WebServerApplicationContext;
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
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * WebSocket proxy implementing first-message authentication for browsers, which cannot set an
 * authorization header during the WebSocket handshake.
 *
 * <p>This handler bypasses the normal Spring Cloud Gateway route pipeline and its global
 * pre-filters by design. The upstream service is responsible for authenticating the token.</p>
 *
 * @author Jon Harper <jon.harper at rte-france.com>
 */
@Component
public class WsDataAuthProxyHandler implements WebSocketHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(WsDataAuthProxyHandler.class);

    private static final Pattern PRINTABLE_ASCII = Pattern.compile("[\\x20-\\x7E]+");

    private static final int MAX_CLOSE_REASON_BYTES = 123;

    private final WsDataAuthProperties properties;

    private final WebServerApplicationContext applicationContext;

    private final ReactorNettyWebSocketClient client = new ReactorNettyWebSocketClient();

    public WsDataAuthProxyHandler(WsDataAuthProperties properties, WebServerApplicationContext applicationContext) {
        this.properties = properties;
        this.applicationContext = applicationContext;
    }

    @Override
    public Mono<Void> handle(WebSocketSession clientSession) {
        AtomicBoolean firstFrameReceived = new AtomicBoolean();
        AtomicBoolean authTimeoutStarted = new AtomicBoolean();
        Mono<Void> proxy = clientSession.receive()
            .switchOnFirst((signal, frames) -> {
                firstFrameReceived.set(true);
                if (!signal.hasValue()) {
                    if (signal.getThrowable() != null) {
                        return Flux.error(signal.getThrowable());
                    }
                    return authTimeoutStarted.get() ? Flux.never() : Flux.empty();
                }
                WebSocketMessage tokenFrame = signal.get();
                if (tokenFrame.getType() != WebSocketMessage.Type.TEXT) {
                    return closeWithPolicyViolation(clientSession, "invalid token frame").thenMany(Flux.empty());
                }
                return proxy(clientSession, frames.skip(1), tokenFrame.getPayloadAsText()).thenMany(Flux.empty());
            })
            .then()
            .onErrorResume(e -> {
                LOGGER.debug("ws-dataauth client session error", e);
                return closeWithServerError(clientSession, "proxy error");
            });
        Mono<Void> authTimeout = Mono.delay(properties.getAuthTimeout())
            .flatMap(ignored -> firstFrameReceived.get()
                    ? Mono.never()
                    : closeAfterAuthTimeout(clientSession, authTimeoutStarted));

        return Mono.firstWithSignal(proxy, authTimeout);
    }

    private static Mono<Void> closeAfterAuthTimeout(WebSocketSession session, AtomicBoolean authTimeoutStarted) {
        authTimeoutStarted.set(true);
        return closeWithPolicyViolation(session, "auth timeout");
    }

    private Mono<Void> proxy(WebSocketSession clientSession, Flux<WebSocketMessage> clientFrames, String token) {
        if (token.isEmpty() || token.getBytes(StandardCharsets.UTF_8).length > properties.getMaxTokenBytes()
                || !PRINTABLE_ASCII.matcher(token).matches()) {
            return closeWithPolicyViolation(clientSession, "invalid token frame");
        }

        URI upstreamUri = buildUpstreamUri(clientSession.getHandshakeInfo().getUri());
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        LOGGER.debug("ws-dataauth proxying to {}", upstreamUri);

        return client.execute(upstreamUri, headers,
                upstreamSession -> relay(clientSession, clientFrames, upstreamSession))
            .onErrorResume(WebSocketClientHandshakeException.class, e -> {
                LOGGER.debug("ws-dataauth upstream handshake rejected for {}", upstreamUri, e);
                return closeWithPolicyViolation(clientSession, "upstream handshake rejected");
            })
            .onErrorResume(e -> {
                LOGGER.debug("ws-dataauth upstream failure for {}", upstreamUri, e);
                return closeWithServerError(clientSession, "upstream connection failed");
            });
    }

    private static Mono<Void> relay(WebSocketSession clientSession, Flux<WebSocketMessage> clientFrames,
                                    WebSocketSession upstreamSession) {
        return Mono.zip(
                upstreamSession.send(retained(clientFrames)),
                clientSession.send(retained(upstreamSession.receive())))
            .then();
    }

    /**
     * Retains relayed frame payloads so they survive until the outbound write completes, and
     * releases any frame discarded on cancellation to avoid leaking pooled Netty buffers.
     */
    private static Flux<WebSocketMessage> retained(Flux<WebSocketMessage> in) {
        return in.map(f -> new WebSocketMessage(f.getType(), DataBufferUtils.retain(f.getPayload())))
                 .doOnDiscard(WebSocketMessage.class, m -> DataBufferUtils.release(m.getPayload()));
    }

    private URI buildUpstreamUri(URI clientUri) {
        String strippedPath = clientUri.getRawPath().substring(WsDataAuthProperties.PATH_PREFIX.length());
        if (strippedPath.isEmpty()) {
            strippedPath = "/";
        }
        String query = clientUri.getRawQuery();
        return URI.create("ws://localhost:" + applicationContext.getWebServer().getPort() + strippedPath
                + (query != null ? "?" + query : ""));
    }

    private static Mono<Void> closeWithPolicyViolation(WebSocketSession session, String reason) {
        return session.close(new CloseStatus(1008, truncateReason(reason)));
    }

    private static Mono<Void> closeWithServerError(WebSocketSession session, String reason) {
        return session.close(new CloseStatus(1011, truncateReason(reason)));
    }

    private static String truncateReason(String reason) {
        if (reason.getBytes(StandardCharsets.UTF_8).length <= MAX_CLOSE_REASON_BYTES) {
            return reason;
        }
        StringBuilder truncated = new StringBuilder();
        int byteCount = 0;
        for (int index = 0; index < reason.length();) {
            int codePoint = reason.codePointAt(index);
            int codePointBytes = new String(Character.toChars(codePoint)).getBytes(StandardCharsets.UTF_8).length;
            if (byteCount + codePointBytes > MAX_CLOSE_REASON_BYTES) {
                break;
            }
            truncated.appendCodePoint(codePoint);
            byteCount += codePointBytes;
            index += Character.charCount(codePoint);
        }
        return truncated.toString();
    }
}
