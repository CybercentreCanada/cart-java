package ca.gc.cyber.inerting.cart;

import com.google.common.io.LittleEndianDataOutputStream;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.primitives.Shorts;
import com.google.gson.JsonObject;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@SuppressWarnings("MissingJavadoc")
public class HeaderTest {

    @Test
    public void testPackUnpackHeader_providedOptionalHeader() throws Exception {

        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");

        // Generate expected optional header
        JsonObject optionalHeader = new JsonObject();
        optionalHeader.addProperty("name", "filename.exe");
        optionalHeader.addProperty("custom", "12345");
        String expectedHeaderText = "{\"custom\":\"12345\",\"name\":\"filename.exe\"}";

        // Header
        Header header = new Header();
        header.setEncryptionKey(key);
        header.setKey(TestUtils.DEFAULT_ARC4_KEY);
        header.setOptionalHeader(optionalHeader);
        header.setReserved(0);
        header.setMajor((short) 1);
        // Optional header length is set during packing

        packAndUnpack(header, key, expectedHeaderText);
    }

    @Test
    public void testPackUnpackHeader_providedKey_providedOptionalHeader() throws Exception {

        SecretKeySpec key = new SecretKeySpec(TestUtils.TEST_KEY, "RC4");

        // Generate expected optional header
        JsonObject optionalHeader = new JsonObject();
        optionalHeader.addProperty("name", "filename.exe");
        String expectedHeaderText = "{\"name\":\"filename.exe\"}";

        // Header
        Header header = new Header();
        header.setEncryptionKey(key);
        header.setKey(new byte[16]);
        header.setOptionalHeader(optionalHeader);
        header.setReserved(0);
        header.setMajor((short) 1);
        // Optional header length is set during packing

        packAndUnpack(header, key, expectedHeaderText);
    }

    @Test
    public void testPackUnpackHeader_noOptionalHeader() throws Exception {

        SecretKeySpec key = new SecretKeySpec(TestUtils.TEST_KEY, "RC4");

        // Header
        Header header = new Header();
        header.setEncryptionKey(key);
        header.setKey(new byte[16]);
        header.setOptionalHeader(null);
        header.setReserved(0);
        header.setMajor((short) 1);
        // Optional header length is set during packing

        packAndUnpack(header, key, null);
    }

    @Test
    public void testUnpack_invalidMagic() throws Exception {

        // Altered magic
        byte[] header =
                Hex.decodeHex("4241525401000000000000000000000000000000000000000000000000000000000000000000".toCharArray());

        assertThrows("This is not a valid CaRT header", CartException.class, () -> {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(header);
            Header.unpackHeader(inputStream, TestUtils.DEFAULT_ARC4_KEY, (short) 1);
        });
    }

    @Test
    public void testUnpack_invalidVersion() throws Exception {

        // Set to version 2
        byte[] header =
                Hex.decodeHex("4341525402000000000000000000000000000000000000000000000000000000000000000000".toCharArray());

        assertThrows("This is not a valid CaRT header", CartException.class, () -> {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(header);
            Header.unpackHeader(inputStream, TestUtils.DEFAULT_ARC4_KEY, (short) 1);
        });
    }

    @Test
    public void testUnpack_invalidReserved() throws Exception {

        // Altered reserved
        byte[] header =
                Hex.decodeHex("4341525401000000100000000000000000000000000000000000000000000000000000000000".toCharArray());

        assertThrows("This is not a valid CaRT header", CartException.class, () -> {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(header);
            Header.unpackHeader(inputStream, TestUtils.DEFAULT_ARC4_KEY, (short) 1);
        });
    }

    @Test
    public void testUnpack_wrongKey() throws Exception {

        // Encrypted using default key
        byte[] header =
                Hex.decodeHex("4341525401000000000000000000030104010509020603010401050902062800000000000000c2a4a8484dc40ea0792f74953300d4909dca8b53f3211935705808dfecbd38227d7f1c916b3125f1".toCharArray());

        // Decrypt using TEST_KEY - will decrypt, but the its output will be un-parsable
        assertThrows("Failed to parse the optional header.", CartException.class, () -> {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(header);
            Header.unpackHeader(inputStream, TestUtils.TEST_KEY, (short) 1);
        });
    }

    /**
     * Pack the header, validate it, then unpack it and confirm the parsed header matches the original.
     *
     * @param header             Header to pack
     * @param key                cipher key
     * @param expectedHeaderText expected optional header byte stream
     * @throws Exception If any issues are encountered
     */
    private void packAndUnpack(Header header, SecretKeySpec key, String expectedHeaderText) throws Exception {

        // Pack
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        LittleEndianDataOutputStream dataOutput = new LittleEndianDataOutputStream(outputStream);
        Header.packHeader(header, dataOutput, key);
        byte[] writtenHeader = outputStream.toByteArray();

        // Confirm packed header is as expected
        byte[] expectedHeader = generateExpectedHeader(header, expectedHeaderText);

        byte[] buiffer = new byte[271];
        IOUtils.read(getClass().getResourceAsStream("/withProvidedKey.cart"), buiffer);
        assertArrayEquals(expectedHeader, writtenHeader);

        // unpack
        ByteArrayInputStream inputStream = new ByteArrayInputStream(writtenHeader);
        Header parsedHeader = Header.unpackHeader(inputStream, key.getEncoded(), header.getMajor());

        // Confirm parsed header is as expected
        assertHeaderEquals(header, parsedHeader);
    }

    /**
     * Generate expected header byte stream
     *
     * @param header             Header data
     * @param expectedHeaderText JSON formatted expected text (sorted)
     * @return byte[]
     */
    private static byte[] generateExpectedHeader(Header header, String expectedHeaderText) throws Exception {

        byte[] expectedMagic = "CART".getBytes();
        byte[] expectedVersion = Shorts.toByteArray(Short.reverseBytes(header.getMajor()));
        byte[] expectedReserved = new byte[8];

        Cipher cipher = InternalCartUtils.initCipher(header.getEncryptionKey());
        byte[] encryptedOptionalHeader;
        byte[] encryptedOptionalHeaderLength;
        if (header.getOptionalHeader() == null) {
            encryptedOptionalHeader = new byte[0];
            encryptedOptionalHeaderLength = new byte[8];
        } else {
            String optionalHeader = expectedHeaderText;
            encryptedOptionalHeader = cipher.doFinal(optionalHeader.getBytes());
            encryptedOptionalHeaderLength = Longs.toByteArray(Long.reverseBytes(encryptedOptionalHeader.length));
        }

        return Bytes.concat(expectedMagic, expectedVersion, expectedReserved, header.getKey(), encryptedOptionalHeaderLength, encryptedOptionalHeader);
    }

    /**
     * Confirm that the actual header corresponds to the expected header
     *
     * @param expected The expected header.
     * @param actual   The expected footer.
     */
    private static void assertHeaderEquals(Header expected, Header actual) {

        assertArrayEquals(expected.getEncryptionKey().getEncoded(), actual.getEncryptionKey().getEncoded());
        assertArrayEquals(expected.getKey(), actual.getKey());
        assertEquals(expected.getMajor(), actual.getMajor());
        assertEquals(expected.getReserved(), actual.getReserved());
        assertEquals(expected.getOptionalHeader(), actual.getOptionalHeader());
        assertEquals(expected.getOptionalHeaderLength(), actual.getOptionalHeaderLength());
        assertEquals(expected.getTotalLength(), actual.getTotalLength());
    }
}
