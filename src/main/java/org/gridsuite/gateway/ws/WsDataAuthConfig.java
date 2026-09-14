/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.ws;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;

import java.util.Map;

/**
 * Registers the {@link WsDataAuthProxyHandler} on {@code /ws-dataauth/**} with a handler
 * mapping order of {@code -1}, i.e. before Spring Cloud Gateway's
 * {@code RoutePredicateHandlerMapping} (order {@code 1}). All other paths are unaffected
 * and continue to be handled by the normal gateway routes.
 *
 * <p>NOTE: gateway global pre-filters (e.g. {@code TokenValidatorGlobalPreFilter}) only apply
 * to gateway routes; they are intentionally bypassed for this endpoint. Authentication is
 * delegated to the upstream service which receives the token from the first WebSocket frame
 * as an {@code Authorization: Bearer} header.</p>
 *
 * @author Jon Harper <jon.harper at rte-france.com>
 */
@Configuration
@EnableConfigurationProperties(WsDataAuthProperties.class)
@ConditionalOnProperty(prefix = "ws-dataauth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class WsDataAuthConfig {

    @Bean
    public HandlerMapping wsDataAuthHandlerMapping(WsDataAuthProxyHandler handler) {
        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping(
                Map.of(WsDataAuthProperties.PATH_PREFIX + "/**", handler));
        mapping.setOrder(-1); // before RoutePredicateHandlerMapping (order 1)
        return mapping;
    }
}
