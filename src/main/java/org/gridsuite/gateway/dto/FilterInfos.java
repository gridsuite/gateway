package org.gridsuite.gateway.dto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.web.server.ServerWebExchange;

@AllArgsConstructor
@Data
public class FilterInfos {
    private final ServerWebExchange exchange;
    private final GatewayFilterChain chain;
    private final JWT jwt;
    private final JWTClaimsSet jwtClaimsSet;
    private final Issuer iss;
    private final ClientID clientID;
    private final JWSAlgorithm jwsAlg;
    private final String jwkSetUri;
}
