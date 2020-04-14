package org.gridsuite.gateway;

class GatewayException extends RuntimeException {

    GatewayException(String msg) {
        super(msg);
    }

    GatewayException(String message, Throwable cause) {
        super(message, cause);
    }
}
