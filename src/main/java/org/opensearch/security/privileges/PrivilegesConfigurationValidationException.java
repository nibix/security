package org.opensearch.security.privileges;

/**
 * Thrown when the privileges configuration cannot be parsed because it is invalid.
 */
public class PrivilegesConfigurationValidationException extends Exception {
    public PrivilegesConfigurationValidationException(String message) {
        super(message);
    }

    public PrivilegesConfigurationValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}

