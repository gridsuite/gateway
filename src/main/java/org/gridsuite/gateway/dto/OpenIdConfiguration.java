package org.gridsuite.gateway.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;

public class OpenIdConfiguration {
    @JsonAlias("jwks_uri")
    String jwksUri;

    @JsonGetter("jwksUri")
    public String getJwksUri() {
        return jwksUri;
    }

    @JsonSetter("jwksUri")
    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }
}
