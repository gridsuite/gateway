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

// Enable Netty metrics that are not enabled by default in Spring Boot.
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
            // Allow only the specific reactor metrics that we use.
            // If additional metrics are added, ensure the URIs are provided in a template-like format.
            // Without this, each unique URI generates a separate tag, which takes a lot of memory.
            return name.equals("reactor.netty.http.server.connections") ||
                    name.equals("reactor.netty.http.server.connections.active");
        });
    }
}
