package ca.gc.cyber.inerting.cart;

import com.google.common.io.LittleEndianDataInputStream;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataOutput;
import java.io.IOException;

/**
 * Package internal class that holds the values for the mandatory and optional footer.
 */
final class Footer {

    /**
     * Reserved field value
     */
    private static final long RESERVED = 0L;

    /**
     * File attributes
     */
    private String sha256;
    private String sha1;
    private String md5;
    private Long fileLength = null;

    /**
     * Length in bytes of the optional footer
     */
    private long optionalFooterLength;

    /**
     * Optional footer in JSON format
     */
    private JsonElement optionalFooter;

    /**
     * Index in the CaRT file where the optional footer begins
     */
    private long startPosition;

    /**
     * Value of the reserved field
     */
    private long reserved;

    /**
     * @return the sha256
     */
    String getSha256() {
        return sha256;
    }

    /**
     * @param sha256 the sha256 to set
     */
    void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    /**
     * @return the sha1
     */
    String getSha1() {
        return sha1;
    }

    /**
     * @param sha1 the sha1 to set
     */
    void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * @return the md5
     */
    String getMd5() {
        return md5;
    }

    /**
     * @param md5 the md5 to set
     */
    void setMd5(String md5) {
        this.md5 = md5;
    }

    /**
     * @return the fileLength
     */
    Long getFileLength() {
        return fileLength;
    }

    /**
     * @param fileLength the fileLength to set
     */
    void setFileLength(Long fileLength) {
        this.fileLength = fileLength;
    }

    /**
     * @return the optionalFooterLength
     */
    long getOptionalFooterLength() {
        return optionalFooterLength;
    }

    /**
     * @param optionalFooterLength the optionalFooterLength to set
     */
    void setOptionalFooterLength(long optionalFooterLength) {
        this.optionalFooterLength = optionalFooterLength;
    }

    /**
     * @return the optionalFooter
     */
    JsonElement getOptionalFooter() {
        return optionalFooter;
    }

    /**
     * @param optionalFooter the optionalFooter to set
     */
    void setOptionalFooter(JsonElement optionalFooter) {
        this.optionalFooter = optionalFooter;
    }

    /**
     * @return the startPosition
     */
    long getStartPosition() {
        return startPosition;
    }

    /**
     * @param startPosition the startPosition to set
     */
    void setStartPosition(long startPosition) {
        this.startPosition = startPosition;
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
     * Convert the footer into a byte stream and write this byte stream to the given {@link DataOutput}. The footer is
     * encrypted using the passed in key.
     *
     * @param footer Footer to write as a byte stream
     * @param output DataOutput to write the footer byte stream to
     * @param key    Encryption key
     * @throws CartException If any issues are encountered
     */
    static void packFooter(Footer footer, DataOutput output, SecretKeySpec key) throws CartException {

        long optFooterLen = 0;
        byte[] optFooterCrypt;

        // Add to the optional footer the hash values and the file length
        JsonElement optionalFooter = footer.getOptionalFooter();
        if (optionalFooter == null) {
            optionalFooter = JsonParser.parseString("{}");
        }
        JsonObject optFooterObj = optionalFooter.getAsJsonObject();
        addPropertyIfNotNull(optFooterObj, "sha256", footer.getSha256());
        addPropertyIfNotNull(optFooterObj, "length", footer.getFileLength());
        addPropertyIfNotNull(optFooterObj, "sha1", footer.getSha1());
        addPropertyIfNotNull(optFooterObj, "md5", footer.getMd5());

        // Encrypt the optional footer
        Cipher cipher = InternalCartUtils.initCipher(key);
        JsonElement sortedOptionalFooter = InternalCartUtils.sortByKey(optFooterObj);
        String footerAsString = sortedOptionalFooter.toString();
        try {
            optFooterCrypt = cipher.doFinal(footerAsString.getBytes());
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new CartException("Failed to encrypt the optional footer.", e);
        }
        optFooterLen = optFooterCrypt.length;
        footer.setOptionalFooter(optionalFooter);
        footer.setOptionalFooterLength(optFooterLen);

        // Write the footer byte stream
        try {
            output.write(optFooterCrypt);
            output.write(CartUtils.TRAC_MAGIC.getBytes());
            output.writeLong(RESERVED);
            output.writeLong(footer.getStartPosition());
            output.writeLong(optFooterLen);
        } catch (IOException e) {
            throw new CartException("Failed to write the footer.", e);
        }
    }

    /**
     * Parse the footer byte stream. The footer parts are first extracted, then the optional footer is decrypted and
     * converted to JSON.
     *
     * @param footer Footer byte stream to parse
     * @param rc4Key Decryption key
     * @return Parsed Footer
     * @throws CartException If any issues are encountered
     */
    static Footer unpackFooter(byte[] footer, SecretKeySpec rc4Key) throws CartException {

        Cipher cipher = InternalCartUtils.initCipher(rc4Key);

        int optionalFooterLength = footer.length - CartUtils.MANDATORY_FOOTER_LENGTH;
        byte[] cipherText = new byte[optionalFooterLength];
        byte[] reversedMagic = new byte[CartUtils.TRAC_MAGIC.length()];
        long reserved;
        long optionalFooterStartPosition;
        long optionalFooterLengthFromFooter;

        // Parse footer elements
        try (LittleEndianDataInputStream dataIS = new LittleEndianDataInputStream(new ByteArrayInputStream(footer))) {
            dataIS.readFully(cipherText);
            dataIS.readFully(reversedMagic);
            reserved = dataIS.readLong();
            optionalFooterStartPosition = dataIS.readLong();
            optionalFooterLengthFromFooter = dataIS.readLong();
        } catch (IOException e) {
            throw new CartException("Failed to unpack the footer.", e);
        }

        // Validate the mandatory footer
        if (!CartUtils.TRAC_MAGIC.equals(new String(reversedMagic)) || reserved != 0) {
            throw new CartException("This is not a valid CaRT mandatory footer");
        }

        // Decrypt the optional footer
        byte[] optionalFooterRaw;
        try {
            optionalFooterRaw = cipher.doFinal(cipherText);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new CartException("Failed to decrypt the optional footer.", e);
        }

        // Convert the optional footer to JSON
        JsonElement optFooter;
        try {
            optFooter = JsonParser.parseString(new String(optionalFooterRaw));
        } catch (JsonSyntaxException e) {
            throw new CartException("Failed to parse the optional footer.", e);
        }

        // Populate Footer to be returned
        Footer unpackedFooter = new Footer();
        unpackedFooter.setOptionalFooter(optFooter);
        unpackedFooter.setOptionalFooterLength(optionalFooterLengthFromFooter);
        unpackedFooter.setStartPosition(optionalFooterStartPosition);
        unpackedFooter.setReserved(reserved);

        return unpackedFooter;
    }

    /**
     * Parse the mandatory footer byte stream.
     *
     * @param footer Footer byte stream to parse
     * @return Parsed Footer
     * @throws CartException If any issues are encountered
     */
    static Footer unpackMandatoryFooter(byte[] footer) throws CartException {
        byte[] reversedMagic = new byte[CartUtils.TRAC_MAGIC.length()];
        long reserved;
        long optionalFooterStartPosition;
        long optionalFooterLengthFromFooter;

        // Parse footer elements
        try (LittleEndianDataInputStream dataIS = new LittleEndianDataInputStream(new ByteArrayInputStream(footer))) {
            dataIS.readFully(reversedMagic);
            reserved = dataIS.readLong();
            optionalFooterStartPosition = dataIS.readLong();
            optionalFooterLengthFromFooter = dataIS.readLong();
        } catch (IOException e) {
            throw new CartException("Failed to unpack the footer.", e);
        }

        // Validate the mandatory footer
        if (!CartUtils.TRAC_MAGIC.equals(new String(reversedMagic)) || reserved != 0) {
            throw new CartException("This is not a valid CaRT mandatory footer");
        }

        // Populate Footer to be returned
        Footer unpackedFooter = new Footer();
        unpackedFooter.setOptionalFooterLength(optionalFooterLengthFromFooter);
        unpackedFooter.setStartPosition(optionalFooterStartPosition);
        unpackedFooter.setReserved(reserved);

        return unpackedFooter;
    }

    /**
     * Add the given property to the JSON object only if it is not null.
     *
     * @param jsonObject JSON Object
     * @param name       Name of the property
     * @param value      Value of the poperty
     */
    private static void addPropertyIfNotNull(JsonObject jsonObject, String name, String value) {
        if (value != null) {
            jsonObject.addProperty(name, value);
        }
    }

    /**
     * Add the given property to the JSON object only if it is not null.
     *
     * @param jsonObject JSON Object
     * @param name       Name of the property
     * @param value      Value of the poperty
     */
    private static void addPropertyIfNotNull(JsonObject jsonObject, String name, Long value) {
        if (value != null) {
            jsonObject.addProperty(name, "" + value);
        }
    }
}
