package ca.gc.cyber.inerting.cart;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@SuppressWarnings("MissingJavadoc")
public class InternalCartUtilsTest {

    @Test
    public void testInitCipher_nullKey() {
        assertThrows("Failed to initialize the cipher instance.", CartException.class, () -> InternalCartUtils.initCipher(null));
    }

    @Test
    public void testInitCipher_valid() throws Exception {
        InternalCartUtils.initCipher(new SecretKeySpec(new byte[16], "RC4"));
        // Should not throw any exceptions
    }

    @Test
    public void testGenerateOutputSortedByKey_nullJson() {
        assertEquals("{}", InternalCartUtils.sortByKey(null).toString());
    }

    @Test
    public void testGenerateOutputSortedByKey_oneElement() {
        JsonObject json = new JsonObject();
        json.addProperty("aaa", 123);
        assertEquals("{\"aaa\":123}", InternalCartUtils.sortByKey(json).toString());
    }

    @Test
    public void testGenerateOutputSortedByKey_multipleKeyValuePairs() {
        JsonObject json = new JsonObject();
        json.addProperty("bbb", "123");
        json.addProperty("aaa", 123);
        json.addProperty("zzz", "0123");
        json.addProperty("abc", 111);
        json.addProperty("ABC", true);
        assertEquals("{\"ABC\":true,\"aaa\":123,\"abc\":111,\"bbb\":\"123\",\"zzz\":\"0123\"}", InternalCartUtils.sortByKey(json)
                                                                                                                 .toString());
    }

    @Test
    public void testGenerateOutputSortedByKey_multipleKeyValuePairsWithArraysInHierarchy() throws Exception {
        InputStream jsonIS = Objects.requireNonNull(getClass().getResourceAsStream("/unsorted.json"));
        InputStream expectedJsonIS = Objects.requireNonNull(getClass().getResourceAsStream("/sorted.json"));

        String jsonInput = IOUtils.toString(jsonIS, StandardCharsets.UTF_8);
        String expectedJson = IOUtils.toString(expectedJsonIS, StandardCharsets.UTF_8);
        // Remove EOF char
        expectedJson = expectedJson.substring(0, expectedJson.length() - 1);

        JsonElement element = JsonParser.parseString(jsonInput);

        JsonElement sortedJsonObject = InternalCartUtils.sortByKey(element);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        assertEquals(expectedJson, gson.toJson(sortedJsonObject));
    }
}
