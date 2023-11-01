package ca.gc.cyber.inerting.cart;

import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Perform the calculation of message digests and keep track of the length of the data being processed.
 */
public class MetadataCalculator {

    /**
     * Total length in bytes of the data
     */
    private long length = 0;

    /**
     * Message digests being calculated. They are mapped by the name of their algorithm.
     */
    private final Map<String, MessageDigest> digests = new HashMap<>();

    /**
     * Constructor
     *
     * @param digestAlgorithms List of the names of the digest algorithms that will be computed. A null value indicate
     *                         that no message digest is to be calculated.
     * @throws NoSuchAlgorithmException If the name of an algorithm is not supported by {@link MessageDigest}.
     */
    public MetadataCalculator(List<String> digestAlgorithms) throws NoSuchAlgorithmException {

        init(digestAlgorithms);
    }

    /**
     * Initializes the map of message digests.
     *
     * @param digestAlgorithms Names of the message digest algorithms for which a {@link MessageDigest} needs to be
     *                         created. A null value indicates that not message digest will be computed.
     * @throws NoSuchAlgorithmException If the name of an algorithm is not supported by {@link MessageDigest}.
     */
    private void init(List<String> digestAlgorithms) throws NoSuchAlgorithmException {

        if (digestAlgorithms == null) {
            return;
        }

        for (String digestAlgo : digestAlgorithms) {
            digests.put(digestAlgo, MessageDigest.getInstance(digestAlgo));
        }
    }

    /**
     * Update the data length and the message digests with the given data. Only the first {@code dataLength} will be
     * used to perform the update.
     *
     * @param data       Data to use for the update
     * @param dataLength Length of the data, starting at index 0, to use for the update.
     */
    public void update(byte[] data, int dataLength) {

        if (data != null && dataLength >= 0) {
            length += dataLength;
            for (MessageDigest digest : digests.values()) {
                digest.update(data, 0, dataLength);
            }
        }
    }

    /**
     * Return the digest for the given algorithm. The digest is reset after this method call returned.
     *
     * @param algorithm Name of the message digest algorithm to get the digest for
     * @return Return the hex representation of the message digest of the given algorithm. Returns null if the algorithm
     * was not used by this instance.
     */
    public String getDigest(String algorithm) {
        MessageDigest messageDigest = digests.get(algorithm);

        return messageDigest == null ? null : Hex.encodeHexString(messageDigest.digest());
    }

    /**
     * @return Total length
     */
    public long getLength() {
        return length;
    }
}
