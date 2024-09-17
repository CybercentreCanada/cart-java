package ca.gc.cyber.inerting.cart;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class CartUtilsTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testUnpack() throws IOException, CartException {

        Cart cart = new CartImpl();
        InputStream input = IOUtils.toInputStream("Bonjour Hi!", StandardCharsets.UTF_8);
        Path cartedFile = Path.of(folder.getRoot().getPath(), "testFile.cart");

        OutputStream outputStream = Files.newOutputStream(cartedFile);
        cart.cart(input, outputStream, null, null, null, "testFile.txt");

        InputStream cartedFileInputStream = Files.newInputStream(cartedFile);
        InputStream unpackedInputStream = CartUtils.unpack(cartedFileInputStream);
        assertEquals("Bonjour Hi!", new String(IOUtils.toByteArray(unpackedInputStream)));
    }
}
