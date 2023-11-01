package ca.gc.cyber.inerting.cart;

import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

@SuppressWarnings("MissingJavadoc")
public class MetadataCalculatorTest {

    @Test
    public void testConstructor_nullList() throws NoSuchAlgorithmException {
        new MetadataCalculator(null);

        // Should not throw an exception
    }

    @Test
    public void testConstructor_emptyList() throws NoSuchAlgorithmException {
        new MetadataCalculator(null);

        // Should not throw an exception
    }

    @Test
    public void testConstructor_validAlgorithms() throws NoSuchAlgorithmException {
        new MetadataCalculator(Arrays.asList("MD5", "SHA-256"));
    }

    @Test
    public void testConstructor_invalidAlgorithms() {
        assertThrows(NoSuchAlgorithmException.class, () -> new MetadataCalculator(List.of("X")));
    }

    @Test
    public void testUpdate_nullData() throws Exception {

        MetadataCalculator calc = new MetadataCalculator(List.of("MD5"));

        calc.update(null, 0);

        // Confirm no data was processed
        assertEquals(0, calc.getLength());
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", calc.getDigest("MD5"));
    }

    @Test
    public void testUpdate_NegativeLength() throws Exception {

        MetadataCalculator calc = new MetadataCalculator(List.of("MD5"));

        calc.update(new byte[1], -1);

        // Confirm no data was processed
        assertEquals(0, calc.getLength());
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", calc.getDigest("MD5"));
    }

    @Test
    public void testGetDigest_updateNeverCalled() throws Exception {

        MetadataCalculator calc = new MetadataCalculator(List.of("MD5"));

        // Should return the MD5 for empty data
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", calc.getDigest("MD5"));
        assertEquals(0, calc.getLength());
    }

    @Test
    public void testGetDigest_multipleUpdateCalls() throws Exception {

        String expectedMD5 = "33f564dc93b527ff94fb3dd006595615";
        String expectedSHA256 = "47c16260b2951a7b5f5ee9fb118f729d3c980c02730490f6eaa09a4ac53d5218";

        MetadataCalculator calc = new MetadataCalculator(Arrays.asList("MD5", "SHA-256"));

        calc.update("ABC".getBytes(), 3);
        calc.update("123!!!".getBytes(), 6);
        calc.update("\n\r\t hahaha".getBytes(), 10);

        assertEquals(19, calc.getLength());
        assertEquals(expectedMD5, calc.getDigest("MD5"));
        assertEquals(expectedSHA256, calc.getDigest("SHA-256"));
    }

    @Test
    public void testGetDigest_updateCallForPortionOfTheData() throws Exception {

        String expectedMD5 = "33f564dc93b527ff94fb3dd006595615";
        String expectedSHA256 = "47c16260b2951a7b5f5ee9fb118f729d3c980c02730490f6eaa09a4ac53d5218";

        MetadataCalculator calc = new MetadataCalculator(Arrays.asList("MD5", "SHA-256"));

        calc.update("ABC123!!!\n\r\t hahahaThisIsExtra".getBytes(), 19);

        assertEquals(19, calc.getLength());
        assertEquals(expectedMD5, calc.getDigest("MD5"));
        assertEquals(expectedSHA256, calc.getDigest("SHA-256"));
    }

    @Test
    public void testGetDigest_algoNotUsed() throws Exception {

        MetadataCalculator calc = new MetadataCalculator(List.of("MD5"));
        assertNull(calc.getDigest("SHA-256"));
    }

    @Test
    public void testGetDigest_nullAlgorithm() throws Exception {

        MetadataCalculator calc = new MetadataCalculator(List.of("MD5"));
        assertNull(calc.getDigest(null));
    }
}
