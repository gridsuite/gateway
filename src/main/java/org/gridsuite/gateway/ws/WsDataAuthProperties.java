/*
  Copyright (c) 2026, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway.ws;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration for the first-frame WebSocket authentication proxy endpoint.
 *
 * @author Jon Harper <jon.harper at rte-france.com>
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "ws-dataauth")
public class WsDataAuthProperties {

    /** Path prefix under which the proxy endpoint is exposed. */
    public static final String PATH_PREFIX = "/ws-dataauth";

    /** Whether the endpoint is enabled. */
    private boolean enabled = true;

    /** Maximum time to wait for the first (token) frame from the client. */
    private Duration authTimeout = Duration.ofSeconds(5);

    /** Maximum accepted size, in bytes, of the first (token) frame. */
    private int maxTokenBytes = 8192;
}
