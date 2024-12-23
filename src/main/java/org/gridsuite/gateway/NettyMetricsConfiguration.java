/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import io.micrometer.core.instrument.config.MeterFilter;
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.netty.http.server.HttpServer;

import java.util.function.Function;

/**
 * @author Seddik Yengui <seddik.yengui_externe at rte-france.com>
 */

// the metrics expose by reactor-netty are not enabled by default in spring boot.
// To enable them we add the following bean to customise the Netty HttpServer.
@Configuration
public class NettyMetricsConfiguration implements NettyServerCustomizer {
    @Override
    public HttpServer apply(HttpServer httpServer) {
        return httpServer.metrics(true, Function.identity());
    }

    @Bean
    public MeterFilter meterFilter() {
        return MeterFilter.denyUnless(id -> {
            String name = id.getName();
            // Allow all non-reactor metrics
            if (!name.startsWith("reactor.netty")) {
                return true;
            }
            // Allow only the specific reactor metrics that we use
            return name.equals("reactor.netty.http.server.connections") ||
                    name.equals("reactor.netty.http.server.connections.active");
        });
    }
}
