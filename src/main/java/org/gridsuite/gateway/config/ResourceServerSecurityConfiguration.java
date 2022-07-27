/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import java.util.List;


/**
 * @author bendaamerahm </ahmed.bendaamer@rte-france.com>
 */

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class ResourceServerSecurityConfiguration {

    @Value("${allowed-issuers}")
    private List<String> allowedIssuers;

    JwtIssuerReactiveAuthenticationManagerResolver reactiveAuthenticationManagerResolver;

    @Bean
    public SecurityWebFilterChain securityWebFilterChainForJwtIssuer(ServerHttpSecurity http) {
        reactiveAuthenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(allowedIssuers);
        http
            .authorizeExchange(exchanges -> exchanges
                    .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                    .authenticationManagerResolver(reactiveAuthenticationManagerResolver).bearerTokenConverter(bearerTokenConverter())
            );
        return http.build();
    }

    ServerAuthenticationConverter bearerTokenConverter() {
        ServerBearerTokenAuthenticationConverter bearerTokenConverter = new ServerBearerTokenAuthenticationConverter();
        bearerTokenConverter.setAllowUriQueryParameter(true);
        return bearerTokenConverter;
    }

}
