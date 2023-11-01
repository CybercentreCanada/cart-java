package ca.gc.cyber.inerting.cart;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Cart constants and utilities available to client applications
 */
public final class CartUtils {

    /**
     * Magic representing CART in the header
     */
    public static final String CART_MAGIC = "CART";

    /**
     * Magic representing CART in the footer
     */
    public static final String TRAC_MAGIC = "TRAC";

    /**
     * Total length in bytes of the mandatory header
     */
    public static final int MANDATORY_HEADER_LENGTH = 38;
    /**
     * Total length in bytes of the mandatory footer
     */
    public static final int MANDATORY_FOOTER_LENGTH = 28;

    /**
     * Logger used by this class.
     */
    private static final Logger log = Logger.getLogger(CartUtils.class.getName());

    /**
     * Default constructor.
     */
    private CartUtils() {

    }

    /**
     * Sets up a PipedInputStream and a PipedOutputStream. The PipedOutputStream will be passed to the Consumer and will
     * be closed automatically once the consumer is finished. The PipedInputStream will be returned by the method.
     *
     * @param writer A Consumer that writes to an OutputStream. It will be run in a separate Thread.
     * @return An InputStream that contains whatever is written to the OutputStream provided to the Consumer.
     * @throws IOException If the PipedOutputStream cannot be initialized.
     */
    private static InputStream writeToPipedStream(Consumer<OutputStream> writer) throws IOException {
        // This latch will wait for the PipedOutputStream to be initialized in its thread.
        final CountDownLatch latch = new CountDownLatch(1);
        // If there is an error in the OutputStream's thread, we will pass it out with this reference.
        final AtomicReference<IOException> outputStreamException = new AtomicReference<>();

        /*
         * Sonar will complain about this stream not being properly closed. Since this is returned by the method,
         * it is closed in the client code.
         */
        final PipedInputStream pipedInputStream = new PipedInputStream();
        try {
            // PipedInputStream and PipedOutputStream need to operate in separate threads.
            new Thread(() -> {
                try (PipedOutputStream pipedOutputStream = new PipedOutputStream(pipedInputStream)) {
                    // The PipedOutputStream is setup, so unblock the main thread.
                    latch.countDown();

                    writer.accept(pipedOutputStream);
                } catch (IOException e) {
                    /*
                     * IOException can be thrown by both "new PipedOutputStream()" and "PipedOutputStream.close()"
                     * according to the method signatures. However, close() only includes that in its signature because
                     * that is what OutputStream specifies. In practice (in Java 8), PipedOutputStream.close() will not
                     * throw an IOException, so we can be reasonably certain that the exception is from the constructor.
                     */
                    outputStreamException.set(new IOException("Failed to open PipedOutputStream.", e));
                    // Unblock the main thread so it can handle the exception.
                    latch.countDown();
                }
            }).start();

            // Wait for the PipedOutputStream to be setup.
            try {
                latch.await();
            } catch (InterruptedException e) {
                String message = "Interrupted while waiting for PipedOutputStream to be initialized.";
                log.log(Level.SEVERE, message, e);
                throw new IOException(message, e);
            }

            // Propagate any IOException that occurred during setup of the PipedOutputStream.
            IOException ioe = outputStreamException.get();
            if (ioe != null) {
                log.severe(ioe.getMessage());
                throw ioe;
            }
        } catch (Exception e) {
            /*
             * pipedInputStream is not closed in a "finally" block because we only want to close it if something goes
             * wrong. In the normal case, we do not want to close it because we are returning it from the method so
             * that other code can use it.
             */
            try {
                pipedInputStream.close();
            } catch (IOException ioe) {
                log.log(Level.SEVERE, "Failed to close PipedInputStream", e);
            }

            throw e;
        }

        return pipedInputStream;
    }

    /**
     * Unpack an input stream, returning it in an input stream.
     *
     * @param inputStream The {@link InputStream} to unpack.
     * @return The unpacked {@link InputStream}.
     * @throws IOException      When there are stream issues.
     * @throws RuntimeException when cart fails.
     */
    public static InputStream unpack(InputStream inputStream) throws IOException {
        return writeToPipedStream(outputStream -> {
            try {
                Cart cart = new CartImpl();
                cart.unpack(inputStream, outputStream);
            } catch (CartException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
