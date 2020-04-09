package com.powsybl.gateway;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

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
