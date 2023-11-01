package ca.gc.cyber.inerting.cart;

import com.google.common.io.LittleEndianDataInputStream;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataOutput;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Package internal class that holds the values for the mandatory and optional header.
 */
class Header {
    /**
     * Total length in bytes of the mandatory header
     */
    private static final int MANDATORY_HEADER_LENGTH = 38;

    /**
     * Reserved field value
     */
    private static final int RESERVED = 0;

    /**
     * Total number of bytes used by the magic
     */
    private static final int MAGIC_LENGTH = 4;

    /**
     * Length of the header key field, in bytes
     */
    private static final int HEADER_KEY_FIELD_LENGTH = 16;

    /**
     * Reserved field
     */
    private long reserved = RESERVED;

    /**
     * Major version of the algorithm
     */
    private short major;

    /**
     * Holds the default key if user didn't provide a key, or zeros otherwise
     */
    private byte[] key;

    /**
     * Optional header. Could be null if none provided.
     */
    private JsonElement optionalHeader;

    /**
     * Optional header length, once encrypted
     */
    private long optionalHeaderLength;

    /**
     * Encryption key
     */
    private SecretKeySpec encryptionKey;

    /**
     * @return The total header length
     */
    long getTotalLength() {

        return MANDATORY_HEADER_LENGTH + optionalHeaderLength;
    }

    /**
     * @return the reserved
     */
    long getReserved() {
        return reserved;
    }

    /**
     * @param reserved the reserved to set
     */
    void setReserved(long reserved) {
        this.reserved = reserved;
    }

    /**
     * @return the major
     */
    short getMajor() {
        return major;
    }

    /**
     * @param major the major to set
     */
    void setMajor(short major) {
        this.major = major;
    }

    /**
     * @return the key
     */
    byte[] getKey() {
        return key;
    }

    /**
     * @param key the key to set
     */
    void setKey(byte[] key) {
        if (key == null) {
            this.key = null;
        } else {
            this.key = Arrays.copyOf(key, key.length);
        }
    }

    /**
     * @return the optionalHeader
     */
    JsonElement getOptionalHeader() {
        return optionalHeader;
    }

    /**
     * @param optionalHeader the optionalHeader to set
     */
    void setOptionalHeader(JsonElement optionalHeader) {
        this.optionalHeader = optionalHeader;
    }

    /**
     * @return the optionalHeaderLength
     */
    long getOptionalHeaderLength() {
        return optionalHeaderLength;
    }

    /**
     * @param optionalHeaderLength the optionalHeaderLength to set
     */
    void setOptionalHeaderLength(long optionalHeaderLength) {
        this.optionalHeaderLength = optionalHeaderLength;
    }

    /**
     * @return the encryptionKey
     */
    SecretKeySpec getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * @param encryptionKey the encryptionKey to set
     */
    void setEncryptionKey(SecretKeySpec encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    /**
     * Generate and write the header byte stream on the {@link DataOutput}.
     *
     * @param header     Header to generate a byte stream of
     * @param dataOutput Byte stream is written to this {@link DataOutput}
     * @param key        Encryption key for the optional header
     * @throws CartException If any issues are encountered
     */
    static void packHeader(Header header, DataOutput dataOutput, SecretKeySpec key) throws CartException {

        // Sort by the keys the optional header JSON objects, then encrypt the optional header
        byte[] optHeaderCrypt = null;
        if (header.getOptionalHeader() != null) {
            try {
                Cipher cipher = InternalCartUtils.initCipher(key);
                JsonElement sortedHeader = InternalCartUtils.sortByKey(header.getOptionalHeader());
                optHeaderCrypt = cipher.doFinal(sortedHeader.toString().getBytes());
                header.setOptionalHeaderLength(optHeaderCrypt.length);
            } catch (BadPaddingException | IllegalBlockSizeException e) {
                throw new CartException("Failed to encrypt the optional header.", e);
            }
        }

        // Write the byte stream
        try {
            dataOutput.write(CartUtils.CART_MAGIC.getBytes());
            dataOutput.writeShort(header.getMajor());
            dataOutput.writeLong(header.getReserved());
            dataOutput.write(header.getKey());

            dataOutput.writeLong(header.getOptionalHeaderLength());
            if (header.getOptionalHeaderLength() > 0) {
                dataOutput.write(optHeaderCrypt);
            }
        } catch (IOException e) {
            throw new CartException("Failed to write the header.", e);
        }
    }

    /**
     * Parse the mandatory header elements out of a byte array and store these elements into the Header object.
     *
     * @param headerBytes  CaRT formatted file
     * @param majorVersion Expected value for the major version
     * @return Header
     * @throws CartException If any issues are encountered
     */
    static Header unpackMandatoryHeader(byte[] headerBytes, short majorVersion) throws CartException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(headerBytes)) {
            return Header.unpackMandatoryHeader(inputStream, majorVersion);
        } catch (IOException e) {
            throw new CartException("Failed to unpack mandatory header.", e);
        }
    }

    /**
     * Parse the mandatory header elements out of the input stream and store these elements into the Header object.
     *
     * @param inputStream  CaRT formatted file
     * @param majorVersion Expected value for the major version
     * @return Header
     * @throws CartException If any issues are encountered
     */
    static Header unpackMandatoryHeader(InputStream inputStream, short majorVersion) throws CartException {

        byte[] headerArc4Key = new byte[HEADER_KEY_FIELD_LENGTH];
        byte[] magic = new byte[MAGIC_LENGTH];
        short version;
        long reserved;
        long optionalHeaderLength;
        Header header = new Header();

        try {
            // Can't close this stream, since it close the contained stream too
            LittleEndianDataInputStream dataIS = new LittleEndianDataInputStream(inputStream);

            // Read the mandatory header
            dataIS.readFully(magic);
            version = dataIS.readShort();
            reserved = dataIS.readLong();
            dataIS.readFully(headerArc4Key);
            optionalHeaderLength = dataIS.readLong();
        } catch (IOException e) {
            throw new CartException("Failed to unpack the header.", e);
        }

        // Validate the mandatory header
        if (!CartUtils.CART_MAGIC.equals(new String(magic)) || version != majorVersion || reserved != RESERVED) {
            throw new CartException("This is not a valid CaRT header");
        }

        header.setKey(headerArc4Key);
        header.setMajor(version);
        header.setOptionalHeaderLength(optionalHeaderLength);
        header.setReserved(reserved);

        return header;
    }

    /**
     * Parse the header elements out of a byte array and store these elements into the Header object.
     *
     * @param headerBytes  CaRT formatted file
     * @param arc4Key      User provided key, or null if default key should be used to decrypt the optional header
     * @param majorVersion Expected value for the major version
     * @return Header
     * @throws CartException If any issues are encountered
     */
    static Header unpackHeader(byte[] headerBytes, byte[] arc4Key, short majorVersion) throws CartException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(headerBytes)) {
            return unpackHeader(inputStream, arc4Key, majorVersion);
        } catch (IOException e) {
            throw new CartException("Failed to unpack header.", e);
        }
    }

    /**
     * Parse the header elements out of the input stream and store these elements into the Header object.
     *
     * @param inputStream  CaRT formatted file
     * @param arc4Key      User provided key, or null if default key should be used to decrypt the optional header
     * @param majorVersion Expected value for the major version
     * @return Header
     * @throws CartException If any issues are encountered
     */
    static Header unpackHeader(InputStream inputStream, byte[] arc4Key, short majorVersion) throws CartException {

        Header header = unpackMandatoryHeader(inputStream, majorVersion);

        /*
         * Determine key to use to decrypt the optional header. If the key is provided, that's the key used to decrypt
         * the optional header. Otherwise, the key found in the header is used.
         */
        byte[] decryptionKey;
        if (arc4Key == null) {
            decryptionKey = header.getKey();
        } else {
            decryptionKey = arc4Key;
        }
        SecretKeySpec encryptionKey = new SecretKeySpec(decryptionKey, "RC4");

        // Decrypt and parse optional header
        JsonElement optHeader = null;
        if (header.getOptionalHeaderLength() > 0) {
            // Decrypt
            Cipher cipher = InternalCartUtils.initCipher(encryptionKey);
            byte[] decrypted;
            try {
                // Can't close this stream, since it close the contained stream too
                LittleEndianDataInputStream dataIS = new LittleEndianDataInputStream(inputStream);
                byte[] cipherText;
                // Read the optional header
                cipherText = new byte[(int) header.getOptionalHeaderLength()];
                dataIS.readFully(cipherText);

                decrypted = cipher.doFinal(cipherText);
            } catch (BadPaddingException | IllegalBlockSizeException | IOException e) {
                throw new CartException("Failed to decrypt the optional header.", e);
            }

            // Convert to JSON
            try {
                optHeader = JsonParser.parseString(new String(decrypted));
            } catch (JsonSyntaxException e) {
                throw new CartException("Failed to parse the optional header.", e);
            }
        }

        header.setOptionalHeader(optHeader);
        header.setEncryptionKey(encryptionKey);

        return header;
    }
}
