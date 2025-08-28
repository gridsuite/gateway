package org.gridsuite.gateway.endpoints;

import org.gridsuite.gateway.ServiceURIsConfig;
import org.springframework.stereotype.Component;

@Component(value = NetworkMapServer.ENDPOINT_NAME)
public class NetworkMapServer implements EndPointServer {

    public static final String ENDPOINT_NAME = "network-map";

    private final ServiceURIsConfig servicesURIsConfig;

    public NetworkMapServer(ServiceURIsConfig servicesURIsConfig) {
        this.servicesURIsConfig = servicesURIsConfig;
    }

    @Override
    public String getEndpointBaseUri() {
        return servicesURIsConfig.getNetworkMapServerBaseUri();
    }

    @Override
    public String getEndpointName() {
        return ENDPOINT_NAME;
    }
}
