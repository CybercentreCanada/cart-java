package ca.gc.cyber.inerting.cart;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static org.junit.Assert.assertEquals;

/**
 * Test utilities.
 */
public final class TestUtils {

    /**
     * Default constructor.
     */
    private TestUtils() {

    }

    /**
     * Default key
     */
    public static final byte[] DEFAULT_ARC4_KEY =
            new byte[]{0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06, 0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06};

    /**
     * Key to use as a provided key during unit tests.
     */
    public static final byte[] TEST_KEY =
            new byte[]{(byte) 0xa1, 0x01, (byte) 0xb4, 0x02, (byte) 0xff, 0x03, (byte) 0xd9, (byte) 0x94, 0x50, 0x33,
                    0x76, 0x45};

    /**
     * Assert that the two {@link FileMetadata} are equals.
     *
     * @param expected Expected {@link FileMetadata}
     * @param actual   Actual {@link FileMetadata}
     */
    public static void assertFileMetadataEquals(FileMetadata expected, FileMetadata actual) {

        assertEquals(expected.getLength(), actual.getLength());
        assertEquals(expected.getSha1(), actual.getSha1());
        assertEquals(expected.getSha256(), actual.getSha256());
        assertEquals(expected.getMd5(), actual.getMd5());
        assertEquals(expected.getFilename(), actual.getFilename());
        assertEquals(expected.getOptionalHeader(), actual.getOptionalHeader());
        assertEquals(expected.getOptionalFooter(), actual.getOptionalFooter());
    }

    /**
     * Create a JsonElement that holds the given property and value.
     *
     * @param property Property
     * @param value    Value
     * @return JsonElement
     */
    public static JsonElement createJsonElement(String property, String value) {
        JsonElement element = JsonParser.parseString("{}");
        JsonObject jsonObject = element.getAsJsonObject();
        jsonObject.addProperty(property, value);
        return jsonObject;
    }
}
