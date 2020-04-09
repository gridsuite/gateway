package com.powsybl.gateway;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@EnableHystrix
@Configuration
public class GatewayConfig {

    @Component
    public static class TokenValidatorGlobalPreFilter implements GlobalFilter {
        @Override
        public Mono<Void> filter(
                ServerWebExchange exchange,
                GatewayFilterChain chain) {
            List<String> ls = exchange.getRequest().getHeaders().get("Authorization");
            assert ls != null;
            if (ls.isEmpty()) {
                System.out.println("shit");
            } else {
                String authorization = ls.get(0);
                //String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwUXF4aTVsVlBVZ0hGbl9OdWpkcEVNcWdKZTlnQkoxaUNOLXNUenRYREdnIn0.eyJqdGkiOiI3M2NhM2QzZC0yYjJjLTQ2NWYtODQ0Ni1lNzY5YWY3MGVjMGEiLCJleHAiOjE1ODQ1MjI2OTIsIm5iZiI6MCwiaWF0IjoxNTg0NTIyMDkyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvY2htaXRzIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImRhNjExYjNjLWIyNjUtNDM2Yi1iZGQxLTU3MTdmNzk1Y2Y0MyIsInR5cCI6IkJlYXJlciIsImF6cCI6InNwYSIsImF1dGhfdGltZSI6MTU4NDUyMDc0Nywic2Vzc2lvbl9zdGF0ZSI6IjM2MGVjOWQ4LTUwMmMtNDY3Zi1hODhiLWVjMzBkN2M1NWFhYSIsImFjciI6IjAiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsInVzZXIiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJjaGFtcyBiaGQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0IiwiZ2l2ZW5fbmFtZSI6ImNoYW1zIiwibG9jYWxlIjoiZnIiLCJmYW1pbHlfbmFtZSI6ImJoZCIsImVtYWlsIjoiY2hhbXNlZGRpbmUuYmVuaGFtZWRAZW5zaS11bWEudG4ifQ.aynpHx0f1CUG5x-8N0EdVZs1kN-0G2g99CzNEyAilb0vDgVz8QI1753w71Wr3gCQZYdQfT268QTL2ZB2IK1sF7BEM3_UCj3jfkHeiswaR1GteIXYkEMIh8yx0mVKQ5Sp8Fu9eYyoYMdo43ZOlRxInsPYykKN-VSYJL9PFsyK_kZpABA3bqbFfXkDRoLh4qQbWHitwyqeqNhdTsKquZRes-GgdjTHbzlswPFwALs1OBn1wPSkuJdTBRHLJi58B0Wy5h9rL7S3uBJAOKJFWMfe8PmaAAP9VfFRw-080c_SIK4rlv0-XrTD4eZ7pSGCvbql4AXFNCFdoiVwfyUvqS3Imw";
                String token = authorization.split(" ")[1];
                String publicKeyContent = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq83bh5xttYemaU7RtlEi2GwT/aGg9YCyK1hlnFrREXOSJlV0g6mlH+w2jA07TD0qFHeoiOXVONL8CLaDoxCkIwx7S8RulgXTffjjKWMM+2q8fC7wCktTCagpegwVMfcwP5SlxbbZrQK5GqCeX343+5kKBRhi2FrbNBpkUgBWFTVSfn0r6+eZd3DcuCESuV+dDaTVxnWlm1vsECnfUea9zeF/Qcf196oBg/yPBXbURT7eM4G1y5/bEbmigVi47M8wNnp6GIez4YyTlpJroGTIhVzoCwtCMg3bO2w7KYN0nK7wHnXq5Hl0nn+oJHv0A8XcLDpWxR9+GYNBa/erpAKJAQIDAQAB";

                DecodedJWT jwt = JWT.decode(token);

                KeyFactory kf = null;
                try {
                    kf = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("Exception 1!" + e.getMessage());

                }
                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
                RSAPublicKey pubKey = null;
                try {
                    pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
                } catch (InvalidKeySpecException e) {
                    System.out.println("Exception 2!" + e.getMessage());
                }


                Algorithm algorithm = Algorithm.RSA256(pubKey, null);
                algorithm.verify(jwt);
                System.out.println("Token valid :D");
            }

            System.out.println("Global Pre Filter executed");
            return chain.filter(exchange);
        }
    }

    @Bean
    public RouteLocator myRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(p -> p
                        .path("/study/**")
                        .filters(f ->
                                f.hystrix(config -> config.setName("study")
                                        .setFallbackUri("forward:/studyFallback"))
                                .rewritePath("/study/(.*)", "/$1")
                        )
                        .uri("http://localhost:5001")
                )
                .route(p -> p
                        .path("/case/**")
                        .filters(f ->
                                f.hystrix(config -> config.setName("study")
                                        .setFallbackUri("forward:/caseFallback"))
                                        .rewritePath("/case/(.*)", "/$1")
                        )
                        .uri("http://localhost:5000")
                )
                .build();
    }
}
