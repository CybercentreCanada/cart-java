package ca.gc.cyber.inerting.cart;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The file metadata consists of the optional header and optional footer in JSON format, the total length in bytes of
 * the file being neutered, and the SHA256, SHA1 and MD5 calculated on the file being neutered.
 */
public class FileMetadata {
    /**
     * Name of the file attributes properties found in the footer, automatically populated when formatting the file. Use
     * these properties to access their values from the footer.
     */
    public static final String SHA256_PROPERTY_NAME = "sha256";
    /**
     * SHA1 property name.
     */
    public static final String SHA1_PROPERTY_NAME = "sha1";
    /**
     * MD5 property name.
     */
    public static final String MD5_PROPERTY_NAME = "md5";
    /**
     * File length property name.
     */
    public static final String FILE_LENGTH_PROPERTY_NAME = "length";

    /**
     * Name of the file attributes properties found in the header, automatically populated when formatting the file. Use
     * these properties to access their values from the header.
     */
    public static final String FILE_NAME_PROPERTY = "name";

    /**
     * Optional header in JSON format. It will be null if there is none.
     */
    private final JsonElement optionalHeader;

    /**
     * Optional footer in JSON format. It will be null if there is none.
     */
    private final JsonElement optionalFooter;

    /**
     * Constructor
     *
     * @param optionalHeader Optional header
     * @param optionalFooter Optional footer
     */
    FileMetadata(final JsonElement optionalHeader, final JsonElement optionalFooter) {
        this.optionalFooter = optionalFooter;
        this.optionalHeader = optionalHeader;
    }

    /**
     * @return Total length in bytes of the file being neutered. Will be negative if it was not calculated.
     */
    public long getLength() {
        return getFileLength(optionalFooter);
    }

    /**
     * @return SHA-256 calculated on the file being neutered. It will be null if it was not calculated.
     */
    public String getSha256() {
        return getStringValue(optionalFooter, SHA256_PROPERTY_NAME);
    }

    /**
     * @return MD5 calculated on the file being neutered. It will be null if it was not calculated.
     */
    public String getMd5() {
        return getStringValue(optionalFooter, MD5_PROPERTY_NAME);
    }

    /**
     * @return filename stored in the header, or null if none stored.
     */
    public String getFilename() {
        return getStringValue(optionalHeader, FILE_NAME_PROPERTY);
    }

    /**
     * @return SHA-1 calculated on the file being neutered. It will be null if it was not calculated.
     */
    public String getSha1() {
        return getStringValue(optionalFooter, SHA1_PROPERTY_NAME);
    }

    /**
     * @return Optional header in JSON format. It will be null if there is none.
     */
    public JsonElement getOptionalHeader() {
        return optionalHeader;
    }

    /**
     * @return Optional footer in JSON format. It will be null if there is none.
     */
    public JsonElement getOptionalFooter() {
        return optionalFooter;
    }

    /**
     * Extract the value of the property as a String. If the property does not exist, null is returned.
     *
     * @param jsonElement JSON element to extract the property from
     * @param property    Name of the property
     * @return Extracted value, or null
     */
    private static String getStringValue(JsonElement jsonElement, String property) {

        if (jsonElement != null && jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonElement element = jsonObject.get(property);
            if (element != null) {
                return element.getAsString();
            }
        }

        return null;
    }

    /**
     * Extract the file length as a long.
     *
     * @param jsonElement JSON element to extract the property from
     * @return Extracted value, or null
     */
    private static Long getFileLength(JsonElement jsonElement) {
        if (jsonElement != null && jsonElement.isJsonObject()) {
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonElement element = jsonObject.get(FileMetadata.FILE_LENGTH_PROPERTY_NAME);
            if (element != null) {
                return element.getAsLong();
            }
        }
        return null;
    }
}
