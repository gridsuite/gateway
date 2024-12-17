/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

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
