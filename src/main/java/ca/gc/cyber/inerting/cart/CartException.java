package ca.gc.cyber.inerting.cart;

/**
 * Exception thrown when problems are encountered during the packing a file in CaRT format or unpacking of a CaRT file.
 */
public class CartException extends Exception {

    /**
     * Necessary for all serializable classes. Update this value if this object's signature changes.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message the detail message.
     */
    public CartException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause
     */
    public CartException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause
     *
     * @param cause the cause
     */
    public CartException(Throwable cause) {
        super(cause);
    }
}
