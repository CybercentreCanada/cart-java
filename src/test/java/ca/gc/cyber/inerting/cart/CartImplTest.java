package ca.gc.cyber.inerting.cart;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CartImplTest {
    /**
     * Location of a copy of the python CaRT application. This only needs to be set to a "rea" value if teh @Ignore
     * annotation is removed from {@link #testPack_compareAgainstPythonCart} or {@link #testVeryLargeFile()}.
     */
    private static final Path PYTHON_CART_LOCATION = Paths.get("/usr", "local", "bin", "cart").normalize();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    private File outputFolder;

    @Before
    public void setup() {
        outputFolder = folder.getRoot();
    }

    @Test
    public void testPack_nullInputStream() {

        Cart cart = new CartImpl();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        assertThrows("Input steam is null", IllegalArgumentException.class, () -> {
            cart.pack(null, outputStream);
            cart.pack(null, outputStream, new byte[16]);
            cart.pack(null, outputStream, new byte[16], null, null);
        });
    }

    /**
     * CipherInputStream often returns less than the Cart block size (unlike some other InputStreams
     */
    @Test
    public void testCipherInputStream() throws Exception {
        final Random randy = new Random(10L);
        final File sourceFile = folder.newFile("testCipherInputStream");
        final File resultFile = folder.newFile("testCipherInputStreamCartFile");

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final byte[] aesKeyBytes = new byte[16];
        final byte[] ivBytes = new byte[16];
        randy.nextBytes(aesKeyBytes);
        final Key aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);

        final byte[] testContent = new byte[24 * 1024 * 1024];
        randy.nextBytes(testContent);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(sourceFile), aesCipher);
        cipherOutputStream.write(testContent);
        cipherOutputStream.flush();
        cipherOutputStream.close();

        Cipher aesCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipherDecrypt.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(sourceFile), aesCipherDecrypt);

        Cart cart = new CartImpl();

        FileMetadata fileMetadata = cart.pack(cipherInputStream, new FileOutputStream(resultFile));

        Assert.assertEquals(testContent.length, fileMetadata.getLength());
    }

    @Test
    public void testPack_nullOutputStream() {

        Cart cart = new CartImpl();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);

        assertThrows("Output stream is null", IllegalArgumentException.class, () -> {
            cart.pack(inputStream, null);
            cart.pack(inputStream, null, new byte[16]);
            cart.pack(inputStream, null, new byte[16], null, null);
        });
    }

    @Test
    public void testPack_invalidKeyLength() {

        Cart cart = new CartImpl();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        assertThrows("Provided ARC4 key must be at least 1 byte long.", IllegalArgumentException.class, () -> {
            cart.pack(inputStream, outputStream, new byte[0]);
            cart.pack(inputStream, outputStream, new byte[0], null, null);
        });
    }

    @Test
    public void testUnpack_nullInputStream() {

        Cart cart = new CartImpl();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        assertThrows("Input stream is null.", IllegalArgumentException.class, () -> {
            cart.unpack(null, outputStream);
            cart.unpack(null, outputStream, new byte[16]);
        });
    }

    @Test
    public void testUnpack_nullOutputStream() {

        Cart cart = new CartImpl();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
        assertThrows("Output stream is null.", IllegalArgumentException.class, () -> {
            cart.unpack(inputStream, null);
            cart.unpack(inputStream, null, new byte[16]);
        });
    }

    @Test
    public void testUnpack_invalidKeyLength() {

        Cart cart = new CartImpl();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        assertThrows("Provided ARC4 key must be at least 1 byte long.", IllegalArgumentException.class, () -> cart.unpack(inputStream, outputStream, new byte[0]));
    }

    @Test
    public void testSetBlockSize_invalidSize() {

        CartImpl cart = new CartImpl();

        assertThrows("Block size must be greater than 0.", IllegalArgumentException.class, () -> {
            cart.setBlockSize(0);
            cart.setBlockSize(-1);
        });
    }

    @Test
    public void testGetVersion() {

        Cart cart = new CartImpl();
        assertEquals("CaRT v1.0.4", cart.getVersion());
    }

    /**
     * Perform boundary testing and perform validation against the CLI python cart program
     *
     * @throws Exception If any issues are encountered
     */
    @Ignore
    @Test
    public void testPack_compareAgainstPythonCart() throws Exception {

        CartImpl cart = new CartImpl();

        /*
         * Test different block size and data size combinations
         */
        for (int blockSize = 1; blockSize < 10; blockSize++) {
            cart.setBlockSize(blockSize);

            for (int dataSize = 0; dataSize < 2 * blockSize + 2; dataSize++) {
                File testFile = createTestFile(blockSize, dataSize);
                File expectedCartFile = pythonCart(testFile, null);
                packAndAssert_usingPythonCart(cart, testFile, expectedCartFile, null);
            }
        }

        // Test against different provided key sizes
        Random random = new Random();
        for (int keySize = 1; keySize < 35; keySize++) {
            // Make sure the size is different than the sizes used in the previous for loop
            File testFile = createTestFile(keySize, 30);
            byte[] key = new byte[keySize];
            random.nextBytes(key);
            File expectedCartFile = pythonCart(testFile, key);
            packAndAssert_usingPythonCart(cart, testFile, expectedCartFile, key);
        }
    }

    @Test
    public void testPackUnpack_withDefaultKey() throws Exception {
        testPackUnpack(null, null, null);
    }

    @Test
    public void testPackUnpack_withProvidedKey() throws Exception {
        testPackUnpack(TestUtils.TEST_KEY, null, null);
    }

    @Test
    public void testPackUnpack_withDefaultKey_withOptionalHeader() throws Exception {

        JsonElement providedHeader = TestUtils.createJsonElement("header property", "header value");

        testPackUnpack(null, providedHeader, null);
    }

    @Test
    public void testPackUnpack_withDefaultKey_withOptionalFooter() throws Exception {

        JsonElement providedFooter = TestUtils.createJsonElement("footer property", "footer value");

        testPackUnpack(null, null, providedFooter);
    }

    @Test
    public void testPackUnpack_withDefaultKey_withOptionalHeader_withOptionalFooter() throws Exception {

        JsonElement providedHeader = TestUtils.createJsonElement("header property", "header value");
        JsonElement providedFooter = TestUtils.createJsonElement("footer property", "footer value");

        testPackUnpack(null, providedHeader, providedFooter);
    }

    @Test
    public void testPackUnpack_withProvidedKey_withOptionalHeader() throws Exception {

        JsonElement providedHeader = TestUtils.createJsonElement("header property", "header value");

        testPackUnpack(TestUtils.TEST_KEY, providedHeader, null);
    }

    @Test
    public void testPackUnpack_withProvidedKey_withOptionalFooter() throws Exception {

        JsonElement providedFooter = TestUtils.createJsonElement("footer property", "footer value");

        testPackUnpack(TestUtils.TEST_KEY, null, providedFooter);
    }

    @Test
    public void testPackUnpack_withProvidedKey_withOptionalHeader_withOptionalFooter() throws Exception {

        JsonElement providedHeader = TestUtils.createJsonElement("header property", "header value");
        JsonElement providedFooter = TestUtils.createJsonElement("footer property", "footer value");

        testPackUnpack(TestUtils.TEST_KEY, providedHeader, providedFooter);
    }

    @Test
    public void testUnpack_wrongKey() {

        Cart cart = new CartImpl();
        File outputFolder = folder.getRoot();
        File uncartOutputFile = new File(outputFolder.getPath() + File.separator + "nonCartFile.uncart");

        assertThrows("Failed to unpack.", CartException.class, () -> {
            // Decrypt using provided key, while it was encrypted using the default key
            try (InputStream inputStream = getClass().getResourceAsStream("/withProvidedKey.cart");
                 FileOutputStream outputStream = new FileOutputStream(uncartOutputFile)) {
                cart.unpack(inputStream, outputStream, TestUtils.TEST_KEY);
            }
        });
    }

    @Test
    public void testUnpack_nonCartFile() {

        Cart cart = new CartImpl();
        File outputFolder = folder.getRoot();
        File uncartOutputFile = new File(outputFolder.getPath() + File.separator + "nonCartFile.uncart");

        assertThrows("Failed to unpack.", CartException.class, () -> {
            try (InputStream inputStream = getClass().getResourceAsStream("/withProvidedKey");
                 FileOutputStream outputStream = new FileOutputStream(uncartOutputFile)) {
                cart.unpack(inputStream, outputStream);
            }
        });
    }

    @Test
    public void testIsCart_alreadyInCartFormat() throws Exception {

        Cart cart = new CartImpl();

        try (InputStream cartInputStream = getClass().getResourceAsStream("/withDefaultKey.cart")) {
            assertTrue(cart.isCart(cartInputStream, TestUtils.DEFAULT_ARC4_KEY));
        }
    }

    @Test
    public void testIsCart_notInCartFormat() throws Exception {

        Cart cart = new CartImpl();

        try (InputStream cartInputStream = getClass().getResourceAsStream("/withDefaultKey")) {
            assertFalse(cart.isCart(cartInputStream, TestUtils.DEFAULT_ARC4_KEY));
        }
    }

    @Test
    public void testCart_inputAlreadyInCart() throws Exception {

        Cart cart = new CartImpl();
        File outputFolder = folder.getRoot();
        File outputFile = new File(outputFolder.getPath() + File.separator + "withDefaultKey.uncart");

        JsonObject expectedHeader = new JsonObject();
        expectedHeader.addProperty("name", "withDefaultKey");
        FileMetadata expectedFileMetadata = createExpectedFileMetadataForFileWithDefaultKey(expectedHeader, null);

        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey.cart");
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            FileMetadata fileMetadata = cart.cart(inputStream, outputStream, null, null, null, null);
            TestUtils.assertFileMetadataEquals(expectedFileMetadata, fileMetadata);
        }

        // Confirm output file is the same as the original file
        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey");
             FileInputStream outputFileInputStream = new FileInputStream(outputFile)) {
            assertTrue(IOUtils.contentEquals(inputStream, outputFileInputStream));
        }
    }

    @Test
    public void testCart_inputNotInCart_filenameProvided() throws Exception {

        Cart cart = new CartImpl();
        File outputFolder = folder.getRoot();
        File outputFile = new File(outputFolder.getPath() + File.separator + "withDefaultKey.cart");

        JsonObject expectedHeader = new JsonObject();
        expectedHeader.addProperty("name", "withDefaultKey");
        FileMetadata expectedFileMetadata = createExpectedFileMetadataForFileWithDefaultKey(expectedHeader, null);

        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey");
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            FileMetadata fileMetadata = cart.cart(inputStream, outputStream, null, null, null, "withDefaultKey");
            TestUtils.assertFileMetadataEquals(expectedFileMetadata, fileMetadata);
        }

        // Confirm output file is the expected CaRT file
        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey.cart");
             FileInputStream outputFileInputStream = new FileInputStream(outputFile)) {
            assertTrue(IOUtils.contentEquals(inputStream, outputFileInputStream));
        }
    }

    @Test
    public void testCart_inputNotInCart_noFilenameProvided() throws Exception {

        Cart cart = new CartImpl();
        File outputFolder = folder.getRoot();
        File outputFile = new File(outputFolder.getPath() + File.separator + "withDefaultKey.cart");

        FileMetadata expectedFileMetadata = createExpectedFileMetadataForFileWithDefaultKey(null, null);

        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey");
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            FileMetadata fileMetadata = cart.cart(inputStream, outputStream, null, null, null, null);
            TestUtils.assertFileMetadataEquals(expectedFileMetadata, fileMetadata);
        }

        // Confirm output file is the expected CaRT file
        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey_nofilename.cart");
             FileInputStream outputFileInputStream = new FileInputStream(outputFile)) {
            assertTrue(IOUtils.contentEquals(inputStream, outputFileInputStream));
        }
    }

    @Test
    public void testGetFileMetadata_fileIsNull() {
        assertThrows("File is null", IllegalArgumentException.class, () -> {
            //noinspection ConstantConditions
            new CartImpl().getFileMetadata(null, null);
        });
    }

    @Test
    public void testGetFileMetadata_fileNotFound() {
        assertThrows("File not found /a/b/c", CartException.class, () -> new CartImpl().getFileMetadata(new File("/a/b/c"), null));
    }

    @Test
    public void testGetFileMetadata_notCartFile() {
        assertThrows("Failed to unpack the header", CartException.class, () -> {
            URI uri = Objects.requireNonNull(getClass().getResource("/withDefaultKey")).toURI();
            File file = new File(uri);
            new CartImpl().getFileMetadata(file, null);
        });
    }

    @Test
    public void testGetFileMetadata_cartFile() throws Exception {

        Cart cart = new CartImpl();
        JsonElement optionalHeader = getOptionalHeader("withDefaultKey");
        FileMetadata expectedMetadata = createExpectedFileMetadataForFileWithDefaultKey(optionalHeader, null);

        URI uri = Objects.requireNonNull(getClass().getResource("/withDefaultKey.cart")).toURI();
        File file = new File(uri);
        FileMetadata metadata = cart.getFileMetadata(file, null);
        TestUtils.assertFileMetadataEquals(expectedMetadata, metadata);
    }

    /**
     * Execute the pack method with the provided key, provided header and provided footer. The FileMetadata is validated
     * to confirm it contains expected values. The header of the CaRT file validated to confirm it contains the valid
     * key value.
     * <p>
     * Then an unpack of the created CaRT file is performed to confirm the original file is obtained and that the unpack
     * returns the expected FileMtadata.
     *
     * @param providedKey            Provided key, or null to use default
     * @param providedOptionalHeader Provided header, or null if none
     * @param providedOptionalFooter Provided footer, or null if none
     * @throws Exception If any issues are encountered
     */
    private void testPackUnpack(byte[] providedKey, JsonElement providedOptionalHeader,
                                JsonElement providedOptionalFooter) throws Exception {
        Cart cart = new CartImpl();

        File outputFolder = folder.getRoot();
        File cartOutputFile = new File(outputFolder.getPath() + File.separator + "withDefaultKey.cart");

        FileMetadata expectedFileMetadata =
                createExpectedFileMetadataForFileWithDefaultKey(providedOptionalHeader, providedOptionalFooter);

        // Pack and validate metadata
        try (InputStream inputStream = getClass().getResourceAsStream("/withDefaultKey");
             FileOutputStream outputStream = new FileOutputStream(cartOutputFile)) {
            FileMetadata metadata =
                    cart.pack(inputStream, outputStream, providedKey, providedOptionalHeader, providedOptionalFooter);
            TestUtils.assertFileMetadataEquals(expectedFileMetadata, metadata);
        }

        // Make sure the default key is present in header when used, or else the key is all 0's
        try (FileInputStream inputStream = new FileInputStream(cartOutputFile)) {
            byte[] fileContent = IOUtils.toByteArray(inputStream);
            byte[] keyInHeader = new byte[16];
            byte[] expectedKeyInHeader = new byte[16];
            System.arraycopy(fileContent, 14, keyInHeader, 0, 16);
            if (providedKey == null) {
                expectedKeyInHeader = TestUtils.DEFAULT_ARC4_KEY;
            }
            assertArrayEquals(expectedKeyInHeader, keyInHeader);
        }

        // Unpack and confirm original file obtained
        File uncartOutputFile = new File(outputFolder.getPath() + File.separator + "withDefaultKey.uncart");
        try (FileInputStream inputStream = new FileInputStream(cartOutputFile);
             FileOutputStream outputStream = new FileOutputStream(uncartOutputFile);
             FileInputStream uncartFIS = new FileInputStream(uncartOutputFile)) {
            FileMetadata metadata = cart.unpack(inputStream, outputStream, providedKey);
            assertTrue(IOUtils.contentEquals(getClass().getResourceAsStream("/withDefaultKey"), uncartFIS));
            TestUtils.assertFileMetadataEquals(expectedFileMetadata, metadata);
        }
    }

    /**
     * Create the expected {@link FileMetadata} for the resource file 'withDefaultKey'
     *
     * @param providedOptionalHeader optional header
     * @param providedOptionalFooter optional footer
     * @return {@link FileMetadata}
     */
    private FileMetadata createExpectedFileMetadataForFileWithDefaultKey(JsonElement providedOptionalHeader,
                                                                         JsonElement providedOptionalFooter) {

        // Determine expected footer
        JsonObject expectedFooter;
        if (providedOptionalFooter == null) {
            expectedFooter = new JsonObject();
        } else {
            expectedFooter = providedOptionalFooter.getAsJsonObject();
        }

        expectedFooter.addProperty("sha256", "8cddc41319a84a11ea957989dc4c3d66f44daf2cf1549fc4598c6ebee64c64ee");
        expectedFooter.addProperty("length", "25");
        expectedFooter.addProperty("sha1", "6316106a81e7509432f949e267874f4500becbe5");
        expectedFooter.addProperty("md5", "990e869d25cfbf7e4a84cc08bef07a02");

        return new FileMetadata(providedOptionalHeader, expectedFooter);
    }

    /**
     * Call the python cart program against the passed file.
     *
     * @param testFile File to cart
     * @return 'cart'ed File
     * @throws Exception If any issues are encountered
     */
    private File pythonCart(File testFile, byte[] providedKey) throws Exception {
        assertTrue(
                "In order to run ths test, CartImplTest.PYTHON_CART_LOCATION must point to a copy of the python CaRT executable (current value is: "
                        + PYTHON_CART_LOCATION.toString() + ").", Files.isExecutable(PYTHON_CART_LOCATION));

        String cartFile = testFile.getPath() + ".cart";

        List<String> args = new ArrayList<>();
        args.add(PYTHON_CART_LOCATION.toString());
        args.add("-o");
        args.add(cartFile);

        if (providedKey != null) {
            args.add("-k");
            args.add(Base64.getEncoder().encodeToString(providedKey));
        }

        args.add(testFile.getPath());

        new ProcessBuilder().command(args).start().waitFor();

        return new File(cartFile);
    }

    /**
     * Create a test file that will reside in the {@code outputFolder}. The file will contain random bytes, and will be
     * of the given {@code dataSize}.
     *
     * @param blockSize If greater than or equal to 0, will be appended to the file name.
     * @param dataSize  Size of the file to create
     * @return File
     * @throws Exception If any issues are encountered
     */
    private File createTestFile(int blockSize, int dataSize) throws Exception {

        String filePath;
        if (blockSize >= 0) {
            filePath = outputFolder.getPath() + File.separator + "testFile" + blockSize + "_" + dataSize + ".bin";
        } else {
            filePath = outputFolder.getPath() + File.separator + "testFile" + dataSize + ".bin";
        }

        File testFile = new File(filePath);

        byte[] data = new byte[dataSize];
        Random random = new Random();
        random.nextBytes(data);

        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            IOUtils.write(data, fos);
        }

        return testFile;
    }

    /**
     * Assert that the expected and actual files have the same content.
     *
     * @param expected Expected file
     * @param actual   Actual file
     * @throws IOException If any issues are encountered
     */
    private void assertFileEquals(File expected, File actual) throws IOException {

        try (FileInputStream actualIS = new FileInputStream(actual);
             FileInputStream expectedIS = new FileInputStream(expected)) {
            // NOTE: uncommenting these lines will make the test pass, since the streams will have been consumed
            // System.out.println(Hex.encodeHexString(IOUtils.toByteArray(expectedIS)));
            // System.out.println(Hex.encodeHexString(IOUtils.toByteArray(actualIS)));
            assertTrue(IOUtils.contentEquals(expectedIS, actualIS));
        }
    }

    private void packAndAssert_usingPythonCart(Cart cart, File inputFile, File expectedCartFile, byte[] key)
            throws Exception {

        File outputFolder = folder.getRoot();
        File outputFile = new File(outputFolder.getPath() + File.separator + "out.cart");

        // Pack the file
        JsonElement optionalHeader = getOptionalHeader(inputFile.getName());
        FileInputStream fis = new FileInputStream(inputFile);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            cart.pack(fis, fos, key, optionalHeader, null);
        }

        // Compare against neuter
        assertFileEquals(expectedCartFile, outputFile);

        // Pack then unpack should result in the same original file
        File uncartFile = new File(outputFolder.getPath() + File.separator + "uncart");
        try (FileInputStream cartFile = new FileInputStream(outputFile);
             FileOutputStream fos = new FileOutputStream(uncartFile)) {
            cart.unpack(cartFile, fos, key);
        }

        try (FileInputStream original = new FileInputStream(inputFile);
             FileInputStream actual = new FileInputStream(uncartFile)) {
            assertTrue(IOUtils.contentEquals(original, actual));
        }
    }

    /**
     * This test is used to compare performance with the CLI python cart program and to make sure we can process files
     * larger than what a byte array can take. It is ignored, since it takes more than 6 minutes to complete.
     *
     * @throws Exception If any issues are encountered
     */
    @Test
    @Ignore
    public void testVeryLargeFile() throws Exception {
        CartImpl cart = new CartImpl();

        // As a reference, python cart takes 3 minutes to cart this large file
        File testFile = createLargeTestFile();
        File expectedCartFile = pythonCart(testFile, null);
        packAndAssert_usingPythonCart(cart, testFile, expectedCartFile, null);

        // Confirm metadata can be extracted from a large file
        FileMetadata metadata = cart.getFileMetadata(expectedCartFile, null);
        assertEquals(testFile.length(), metadata.getLength());
    }

    /**
     * Create a large file (~4GB)
     *
     * @return Create file
     * @throws Exception If any issues are encountered
     */
    private File createLargeTestFile() throws Exception {
        Path filePath = outputFolder.toPath().resolve("largeFile.bin");

        byte[] data = new byte[Integer.MAX_VALUE / 10];
        Random random = new Random();

        try (OutputStream fos = Files.newOutputStream(filePath)) {
            for (int i = 0; i < 20; i++) {
                random.nextBytes(data);
                IOUtils.write(data, fos);
            }
        }
        return filePath.toFile();
    }

    /**
     * Return the optional header that holds the name of the file
     *
     * @param filename Name of the file
     * @return {@link JsonElement}
     */
    private JsonElement getOptionalHeader(String filename) {
        String optionalHeader = "{\"name\": \"" + filename + "\"}";
        return JsonParser.parseString(optionalHeader);
    }
}
