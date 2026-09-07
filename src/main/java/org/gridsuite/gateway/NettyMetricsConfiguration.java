/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.config.MeterFilter;
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.context.annotation.Configuration;
import reactor.netty.http.server.HttpServer;

import java.util.List;
import java.util.function.Function;

/**
 * @author Seddik Yengui <seddik.yengui_externe at rte-france.com>
 */

// Enable safe and useful Netty metrics that are not enabled by default in Spring Boot.
@Configuration
public class NettyMetricsConfiguration implements NettyServerCustomizer {

    private static final String REACTOR_NETTY_PREFIX = "reactor.netty";
    // If additional metrics are added, ensure they don't have uri as a tag because we
    // don't map reactor-netty uris to a low cardinality space like fixed uri templates.
    // Otherwise we will get OOMs.
    // see httpServer.metrics() configuration below.
    private static final List<String> ALLOWED_REACTOR_NETTY_METRICS = List.of(
            "reactor.netty.http.server.connections.total",
            "reactor.netty.http.server.connections.active"
    );

    @Override
    public HttpServer apply(HttpServer httpServer) {
        // - The filter is registered here before metrics are enabled to easily
        //   guarantee it's active at the time metrics are produced.
        // - Reactor Netty documents that it registers its meters in Micrometer's
        //   static Metrics.globalRegistry so the filter must be set on the
        //   global registry itself (not the registry setup by spring-boot) otherwise
        //   we get OOM errors
        denyHighCardinalityReactorNettyMetrics(Metrics.globalRegistry);

        // NOTE: here passing Function.identity() as the second argument to
        // httpServer.metrics(), we don't normalize/unify uris which is mandatory
        // to use the metrics that add uri as a tag (otherwise this will cause
        // OOMs), hence the current need to filter and keep only metrics without uri.
        // The reason is that the gateway reverse proxies everything without
        // having a list of endpoints (= uri templates) to map to.
        return httpServer.metrics(true, Function.identity());
    }

    private static void denyHighCardinalityReactorNettyMetrics(MeterRegistry meterRegistry) {
        meterRegistry.config().meterFilter(MeterFilter.denyUnless(id -> {
            String name = id.getName();
            // Don't interfere with other non reactor-netty metrics
            if (!name.startsWith(REACTOR_NETTY_PREFIX)) {
                return true;
            }
            // Allow only the specific reactor metrics that we use
            return ALLOWED_REACTOR_NETTY_METRICS.contains(name);
        }));
    }
}
