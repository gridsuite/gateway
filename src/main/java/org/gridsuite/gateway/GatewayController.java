/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.gateway;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * @author Chamseddine Benhamed <chamseddine.benhamed at rte-france.com>
 */
@RestController
public class GatewayController {

    @RequestMapping("/caseFallback")
    public Mono<String> caseServer() {
        return Mono.just("case server API is taking too long to respond or is down. Please try again later");
    }

    @RequestMapping("/studyFallback")
    public Mono<String> studyServer() {
        return Mono.just("study server API is taking too long to respond or is down. Please try again later");
    }
}
