package ca.gc.cyber.inerting.cart;

import com.google.common.io.LittleEndianDataOutputStream;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.gson.JsonElement;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@SuppressWarnings("MissingJavadoc")
public class FooterTest {

    @Test
    public void testPackUnpackFooter_providedOptionalFooterAddedWithFileMetadata() throws Exception {

        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");

        // Generate expected optional footer
        String expectedOptionalFooterText = "{\"length\":\"0\",\"md5\":\"4b53f44df406a70a6c3e878aa329bf15\","
                + "\"sha1\":\"c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e\","
                + "\"sha256\":\"069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53\"}";
        byte[] expectedOptionalFooter = generateExpectedOptionalFooter(expectedOptionalFooterText, key);

        // Footer
        Footer footer = new Footer();
        footer.setFileLength(0L);
        footer.setMd5("4b53f44df406a70a6c3e878aa329bf15");
        footer.setOptionalFooter(null);
        footer.setReserved(0);
        footer.setSha1("c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e");
        footer.setSha256("069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53");
        footer.setStartPosition(205);
        footer.setOptionalFooterLength(expectedOptionalFooter.length);

        packAndUnpack(footer, expectedOptionalFooter, key);
    }

    @Test
    public void testPackUnpackFooter_providedKey_providedOptionalFooterAddedWithFileMetadata() throws Exception {

        SecretKeySpec key = new SecretKeySpec(TestUtils.TEST_KEY, "RC4");

        // Generate expected optional footer
        String expectedOptionalFooterText = "{\"length\":\"0\",\"md5\":\"4b53f44df406a70a6c3e878aa329bf15\","
                + "\"sha1\":\"c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e\","
                + "\"sha256\":\"069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53\"}";
        byte[] expectedOptionalFooter = generateExpectedOptionalFooter(expectedOptionalFooterText, key);

        // Footer
        Footer footer = new Footer();
        footer.setFileLength(0L);
        footer.setMd5("4b53f44df406a70a6c3e878aa329bf15");
        footer.setOptionalFooter(null);
        footer.setReserved(0);
        footer.setSha1("c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e");
        footer.setSha256("069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53");
        footer.setStartPosition(205);
        footer.setOptionalFooterLength(expectedOptionalFooter.length);

        packAndUnpack(footer, expectedOptionalFooter, key);
    }

    @Test
    public void testPackUnpackFooter_optionalFooterContainsOnlyFileMetadata() throws Exception {
        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");

        // Generate expected optional footer
        String expectedOptionalFooterText = "{\"length\":\"4\",\"md5\":\"4b53f44df406a70a6c3e878aa329bf15\","
                + "\"ppp\":\"123455\",\"sha1\":\"c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e\","
                + "\"sha256\":\"069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53\"}";
        byte[] expectedOptionalFooter = generateExpectedOptionalFooter(expectedOptionalFooterText, key);

        JsonElement optionalFooter = TestUtils.createJsonElement("ppp", "123455");

        // Footer
        Footer footer = new Footer();
        footer.setFileLength(4L);
        footer.setMd5("4b53f44df406a70a6c3e878aa329bf15");
        footer.setOptionalFooter(optionalFooter);
        footer.setReserved(0);
        footer.setSha1("c69ece7e9ebba57df6016b9fbfcc0230b3f01c8e");
        footer.setSha256("069afa388826f336c9a1a98c85dffdea9e125ade54b23924eb40e2d32648ff53");
        footer.setStartPosition(205);
        footer.setOptionalFooterLength(expectedOptionalFooter.length);

        packAndUnpack(footer, expectedOptionalFooter, key);
    }

    /**
     * Pack the footer, validate it, then unpack it and confirm the parsed footer matches the original footer.
     *
     * @param footer                 Footer to pack
     * @param expectedOptionalFooter expected optional footer byte stream
     * @param key                    cipher key
     * @throws Exception If any issues are encountered
     */
    private void packAndUnpack(Footer footer, byte[] expectedOptionalFooter, SecretKeySpec key) throws Exception {

        // Generated expected footer byte stream
        byte[] expectedFooter = generateExpectedFooter(footer, expectedOptionalFooter);

        // Pack
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        LittleEndianDataOutputStream dataOutput = new LittleEndianDataOutputStream(outputStream);
        Footer.packFooter(footer, dataOutput, key);
        byte[] writtenFooter = outputStream.toByteArray();

        // Confirm packed footer is as expected
        assertArrayEquals(expectedFooter, writtenFooter);

        // unpack
        Footer parsedFooter = Footer.unpackFooter(writtenFooter, key);

        // Confirm parsed footer is as expected
        assertFooterEquals(footer, parsedFooter);
    }

    @Test
    public void testPackUnpackFooter_optionalFooterIsEmpty() throws Exception {
        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");
        String expectedOptionalFooterText = "{}";
        byte[] expectedOptionalFooter = generateExpectedOptionalFooter(expectedOptionalFooterText, key);

        // Footer
        Footer footer = new Footer();
        footer.setFileLength(null);
        footer.setOptionalFooter(null);
        footer.setReserved(0);
        footer.setStartPosition(205);
        footer.setOptionalFooterLength(expectedOptionalFooter.length);

        packAndUnpack(footer, expectedOptionalFooter, key);
    }

    @Test
    public void testUnpackFooter_invalidReservedFieldValue() throws Exception {

        // Reserved field modified to hold a value different than 0
        byte[] footer = Hex.decodeHex("c2fb545241430000001000000000cd000000000000000200000000000000".toCharArray());
        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");

        assertThrows("This is not a valid CaRT mandatory footer", CartException.class, () -> Footer.unpackFooter(footer, key));
    }

    @Test
    public void testUnpackFooter_invalidMagicFieldValue() throws Exception {

        // "TRAC" magic altered...
        byte[] footer = Hex.decodeHex("c2fb535241430000000000000000cd000000000000000200000000000000".toCharArray());
        SecretKeySpec key = new SecretKeySpec(TestUtils.DEFAULT_ARC4_KEY, "RC4");

        assertThrows("This is not a valid CaRT mandatory footer", CartException.class, () -> Footer.unpackFooter(footer, key));
    }

    /**
     * Return the optional footer encrypted
     *
     * @param optionalFooter Footer to encrypt
     * @param key            Encryption key
     * @return encrypted footer
     * @throws Exception If any issues are encountered
     */
    private static byte[] generateExpectedOptionalFooter(String optionalFooter, SecretKeySpec key) throws Exception {

        Cipher cipher = InternalCartUtils.initCipher(key);
        return cipher.doFinal(optionalFooter.getBytes());
    }

    /**
     * Generate expected footer byte stream
     *
     * @param footer                 Footer data
     * @param expectedOptionalFooter encrypted optional footer
     * @return byte[]
     */
    private static byte[] generateExpectedFooter(Footer footer, byte[] expectedOptionalFooter) {

        byte[] expectedMagic = "TRAC".getBytes();
        byte[] expectedReserved = new byte[8];
        byte[] expectedFooterStartPosition = Longs.toByteArray(Long.reverseBytes(footer.getStartPosition()));
        byte[] expectedFooterLength = Longs.toByteArray(Long.reverseBytes(footer.getOptionalFooterLength()));
        return Bytes.concat(expectedOptionalFooter, expectedMagic, expectedReserved, expectedFooterStartPosition, expectedFooterLength);
    }

    /**
     * Confirm that the actual footer corresponds to the expected footer
     *
     * @param expected The expected footer.
     * @param actual   The actual footer.
     */
    private static void assertFooterEquals(Footer expected, Footer actual) {

        assertEquals(expected.getOptionalFooter(), actual.getOptionalFooter());
        assertEquals(expected.getOptionalFooterLength(), actual.getOptionalFooterLength());
        assertEquals(expected.getReserved(), actual.getReserved());
        assertEquals(expected.getStartPosition(), actual.getStartPosition());
    }
}
