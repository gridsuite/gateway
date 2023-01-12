/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

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

    @JsonAlias("introspection_endpoint")
    String introspectionEndpoint;

    @JsonGetter("introspectionEndpoint")
    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    @JsonSetter("introspectionEndpoint")
    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }
}
