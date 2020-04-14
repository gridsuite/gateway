package org.gridsuite.gateway.dto;

public class OpenIdConfiguration {
    @SuppressWarnings({"membername"})
    String jwks_uri;

    @SuppressWarnings("methodname")
    public String getJwks_uri() {
        return jwks_uri;
    }

    public void setJwks_uri(String jwks_uri) {
        this.jwks_uri = jwks_uri;
    }
}
