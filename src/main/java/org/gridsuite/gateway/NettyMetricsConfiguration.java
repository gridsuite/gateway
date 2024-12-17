package org.gridsuite.gateway;

import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Configuration;
import reactor.netty.http.server.HttpServer;

import java.util.function.Function;

@Configuration
public class NettyMetricsConfiguration implements NettyServerCustomizer {
    @Override
    public HttpServer apply(HttpServer httpServer) {
        return httpServer.metrics(true, Function.identity());
    }
}
