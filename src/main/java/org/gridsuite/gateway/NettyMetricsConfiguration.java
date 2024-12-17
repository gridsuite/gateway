package org.gridsuite.gateway;

import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Configuration;
import reactor.netty.http.server.HttpServer;

import java.util.function.Function;

// As discussed here https://stackoverflow.com/questions/66028195/spring-webflux-actuator-netty-thread-metrics,
// the metrics expose by reactor-netty are not enabled by default in spring boot. To enable them we add the following bean
@Configuration
public class NettyMetricsConfiguration implements NettyServerCustomizer {
    @Override
    public HttpServer apply(HttpServer httpServer) {
        return httpServer.metrics(true, Function.identity());
    }
}
