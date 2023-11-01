package ca.gc.cyber.inerting.cart;

import com.google.common.base.Preconditions;
import com.google.common.io.LittleEndianDataOutputStream;
import com.google.common.primitives.Bytes;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Implementation of the CaRT file format. See the {@link Cart} interface for the details.
 */
public class CartImpl implements Cart {
    /**
     * Default block size used when reading chunk of data from the input file, or when deflating or inflating chunk of
     * data
     */
    private static final int DEFAULT_BLOCK_SIZE = 64 * 1024;

    /**
     * Default RC4 key, which is 3.1415926 repeated twice
     */
    private static final byte[] DEFAULT_ARC4_KEY =
            new byte[]{0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06, 0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06};

    /**
     * Null RC4 key. It is the value being stored in the mandatory header, replacing the DEFAULT_ARC4_KEY when a key is
     * provided. When the key is provided, the user must provide a key to pack and to unpack.
     */
    private static final byte[] NULL_ARC4_KEY =
            new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    /**
     * This is the compressed output to be returned when the file is empty. It corresponds to what neuter returns.
     */
    private static final byte[] COMPRESSED_EMPTY_FILE = new byte[]{0x78, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01};

    /**
     * Version numbers of this CaRT implementation
     */
    private static final short BUILD_MAJOR = 1;
    private static final short BUILD_MINOR = 0;
    private static final short BUILD_MICRO = 4;

    /**
     * Minimum key length required by RC4
     */
    private static final int MINIMUM_KEY_LENGTH = 1;

    /**
     * Python cart program append 0's to any keys less than 16 bytes long with 0's. This constant is the length of this
     * adjusted key.
     */
    private static final int ADJUSTED_KEY_LENGTH = 16;

    /**
     * Close input streams during unpack/pack
     */
    private final boolean closeStreams;

    /**
     * Block size.
     */
    private int blockSize = DEFAULT_BLOCK_SIZE;

    /**
     * Returns a CartImpl that closes streams during pack/unpack
     */
    public CartImpl() {
        closeStreams = true;
    }

    /**
     * Returns a CartImpl
     *
     * @param closeStreams toggle stream closing behavior during pack/unpack
     */
    public CartImpl(final boolean closeStreams) {
        this.closeStreams = closeStreams;
    }

    /**
     * Set the block size
     *
     * @param blockSize block size
     * @throws IllegalArgumentException if argument is less than or equal to 0
     */
    public void setBlockSize(int blockSize) {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must be greater than 0.");
        }

        this.blockSize = blockSize;
    }

    @Override
    public String getVersion() {
        return "CaRT v" + BUILD_MAJOR + "." + BUILD_MINOR + "." + BUILD_MICRO;
    }

    @Override
    public FileMetadata pack(InputStream inputStream, OutputStream outputStream) throws CartException {
        return pack(inputStream, outputStream, null);
    }

    @Override
    public FileMetadata pack(InputStream inputStream, OutputStream outputStream, byte[] arc4Key) throws CartException {
        return pack(inputStream, outputStream, arc4Key, null, null);
    }

    @Override
    public FileMetadata pack(InputStream inputStream, OutputStream outputStream, byte[] arc4Key,
                             JsonElement optionalHeader, JsonElement optionalFooter) throws CartException {
        Preconditions.checkArgument(inputStream != null, "Input stream is null.");
        Preconditions.checkArgument(outputStream != null, "Output stream is null.");
        Preconditions.checkArgument(
                arc4Key == null || arc4Key.length >= MINIMUM_KEY_LENGTH,
                "Provided ARC4 key must be at least " + MINIMUM_KEY_LENGTH + " byte long.");

        MetadataCalculator metadataCalc;
        try {
            metadataCalc = new MetadataCalculator(Arrays.asList("MD5", "SHA-1", "SHA-256"));
        } catch (NoSuchAlgorithmException e) {
            throw new CartException("Invalid algorithm name passed to the message digest.", e);
        }

        LittleEndianDataOutputStream dataOS = new LittleEndianDataOutputStream(outputStream);
        byte[] adjustedKey = adjustKey(arc4Key);
        Header header = createHeader(adjustedKey, optionalHeader);
        Footer footer;

        try {
            Header.packHeader(header, dataOS, header.getEncryptionKey());

            long compressedChunkLength =
                    compressAndEncrypt(inputStream, dataOS, metadataCalc, header.getEncryptionKey());

            footer = createFooter(metadataCalc, header.getTotalLength() + compressedChunkLength, optionalFooter);
            Footer.packFooter(footer, dataOS, header.getEncryptionKey());
        } finally {
            if (closeStreams) {
                IOUtils.closeQuietly(dataOS);
                IOUtils.closeQuietly(inputStream);
                IOUtils.closeQuietly(outputStream);
            }
        }

        return new FileMetadata(optionalHeader, footer.getOptionalFooter());
    }

    @Override
    public FileMetadata unpack(InputStream inputStream, OutputStream outputStream) throws CartException {
        return unpack(inputStream, outputStream, null);
    }

    @Override
    public FileMetadata unpack(InputStream inputStream, OutputStream outputStream, byte[] arc4Key)
            throws CartException {
        Preconditions.checkArgument(inputStream != null, "Input stream is null.");
        Preconditions.checkArgument(outputStream != null, "Output stream is null.");
        Preconditions.checkArgument(
                arc4Key == null || arc4Key.length >= MINIMUM_KEY_LENGTH,
                "Provided ARC4 key must be at least " + MINIMUM_KEY_LENGTH + " byte long.");

        Footer footer;
        Header header;

        try {
            byte[] adjustedKey = adjustKey(arc4Key);
            header = Header.unpackHeader(inputStream, adjustedKey, BUILD_MAJOR);

            byte[] footerRaw =
                    decryptAndDecompress(inputStream, outputStream, header.getEncryptionKey(), header.getTotalLength());
            footer = Footer.unpackFooter(footerRaw, header.getEncryptionKey());
        } catch (Exception e) {
            throw new CartException("Failed to unpack.", e);
        } finally {
            if (closeStreams) {
                IOUtils.closeQuietly(inputStream);
                IOUtils.closeQuietly(outputStream);
            }
        }

        return new FileMetadata(header.getOptionalHeader(), footer.getOptionalFooter());
    }

    @Override
    public boolean isCart(InputStream inputStream, byte[] arc4Key) {
        try {
            // If the mandatory header unpacks and validates, then it is in CaRT format.
            Header.unpackMandatoryHeader(inputStream, BUILD_MAJOR);
            return true;
        } catch (CartException e) {
            return false;
        }
    }

    @Override
    public FileMetadata cart(InputStream inputStream, OutputStream outputStream, byte[] arc4Key,
                             JsonElement optionalHeader, JsonElement optionalFooter, String filename)
            throws CartException {
        BufferedInputStream bufferedStream = new BufferedInputStream(inputStream);
        bufferedStream.mark(CartUtils.MANDATORY_HEADER_LENGTH);
        boolean isCart = isCart(bufferedStream, arc4Key);

        try {
            bufferedStream.reset();
        } catch (IOException e) {
            throw new CartException("Failed to reset the mark on the input stream.", e);
        }

        if (isCart) {
            return unpack(bufferedStream, outputStream, arc4Key);
        } else {
            JsonElement optHeader = optionalHeader;
            if (filename != null) {
                if (optHeader == null) {
                    optHeader = new JsonObject();
                }
                optHeader.getAsJsonObject().addProperty(FileMetadata.FILE_NAME_PROPERTY, filename);
            }

            return pack(bufferedStream, outputStream, arc4Key, optHeader, optionalFooter);
        }
    }

    /**
     * Append 0's to any keys shorter than 16 bytes
     *
     * @param key Key to adjust if necessary
     * @return adjusted key, or the passed in key if no adjustment was necessary
     */
    private byte[] adjustKey(byte[] key) {
        if (key != null && key.length < ADJUSTED_KEY_LENGTH) {
            return Bytes.ensureCapacity(key, ADJUSTED_KEY_LENGTH, 0x00);
        }

        return key;
    }

    /**
     * Create a {@link Header} instance. The key field that goes in the CaRT formatted file header is determined here.
     * It is the default key if it is used for encrypting the file, otherwise the filed is filled with 0's.
     *
     * @param arc4Key        Encryption key. Could be null if non provided
     * @param optionalHeader Optional header. Could be null is none provided
     * @return {@link Header}
     */
    private Header createHeader(byte[] arc4Key, JsonElement optionalHeader) {
        Header header = new Header();
        header.setMajor(BUILD_MAJOR);
        header.setOptionalHeader(optionalHeader);
        header.setReserved(0);

        if (arc4Key == null) {
            header.setKey(DEFAULT_ARC4_KEY);
            header.setEncryptionKey(new SecretKeySpec(DEFAULT_ARC4_KEY, InternalCartUtils.ALGORITHM));
        } else {
            header.setKey(NULL_ARC4_KEY);
            header.setEncryptionKey(new SecretKeySpec(arc4Key, InternalCartUtils.ALGORITHM));
        }

        return header;
    }

    /**
     * Create a {@link Footer} instance.
     *
     * @param metadataCalc        Metadata calculator used for calculating the hashes and file length
     * @param footerStartPosition Footer start position in the CaRT formatted file
     * @param optionalFooter      Optional footer
     * @return {@link Footer}
     */
    private Footer createFooter(MetadataCalculator metadataCalc, long footerStartPosition, JsonElement optionalFooter) {
        Footer footer = new Footer();
        footer.setFileLength(metadataCalc.getLength());
        footer.setSha1(metadataCalc.getDigest("SHA-1"));
        footer.setMd5(metadataCalc.getDigest("MD5"));
        footer.setSha256(metadataCalc.getDigest("SHA-256"));
        footer.setStartPosition(footerStartPosition);
        footer.setOptionalFooter(optionalFooter);

        return footer;
    }

    /**
     * Compress and encrypt the data from the input stream. Hashes and data length are calculated as the bytes are
     * processed.
     *
     * @param inputStream   Data to compress and encrypt
     * @param dataOutput    Compressed and encrypted data is transferred to this {@link DataOutput}
     * @param metadataCalc  Calculator for the data length and the hashed
     * @param encryptionKey Encryption key
     * @return length of the data once compressed and encrypted
     * @throws CartException If any issues are encountered
     */
    private long compressAndEncrypt(InputStream inputStream, DataOutput dataOutput, MetadataCalculator metadataCalc,
                                    SecretKeySpec encryptionKey) throws CartException {
        byte[] chunk = new byte[blockSize];
        byte[] compressedChunk;
        byte[] cypherChunk;
        int bytesRead = 0;
        long compressedChunkLength = 0;

        Cipher cipher = InternalCartUtils.initCipher(encryptionKey);
        Deflater deflater = new Deflater();
        deflater.setLevel(Deflater.BEST_SPEED);

        // Loop until we process a chunk that is less than the block size, at which point we should have reached the end
        // of the stream.
        do {
            bytesRead = readBytesFromStream(inputStream, chunk);

            // Update the hashes and the file length
            metadataCalc.update(chunk, bytesRead);

            if (bytesRead <= 0 && metadataCalc.getLength() == 0) {
                /*
                 * The file is empty. In this case neuter returns this byte[] where 0x7801 means it is not compressed.
                 * The Java library returns an empty byte array. Bug in Java or Python?
                 */
                compressedChunk = COMPRESSED_EMPTY_FILE;
                compressedChunkLength = compressedChunk.length;
            } else {
                /*
                 * File is not empty, but no more data was read from the stream. Set the chunk size to zero to complete
                 * the deflate steps
                 */
                int chunkSize = Math.max(bytesRead, 0);
                deflater.setInput(chunk, 0, chunkSize);
                if (bytesRead <= 0 || bytesRead < blockSize) {
                    deflater.finish();
                }

                // Compress the data
                byte[] deflateChunk = new byte[blockSize];
                // Closing a ByteArrayOutputStream is unnecessary.
                ByteArrayOutputStream decompressOS = new ByteArrayOutputStream();
                int count = deflater.deflate(deflateChunk);
                while (count > 0 || (count == 0 && !deflater.needsInput())) {
                    compressedChunkLength += count;
                    decompressOS.write(deflateChunk, 0, count);
                    count = deflater.deflate(deflateChunk);
                }

                compressedChunk = decompressOS.toByteArray();
            }

            // Encrypt the data
            cypherChunk = cipher.update(compressedChunk);
            if (cypherChunk == null) {
                cypherChunk = new byte[0];
            }

            try {
                dataOutput.write(cypherChunk);
            } catch (IOException e) {
                throw new CartException("Failed to write to the output stream.", e);
            }
        } while (bytesRead == blockSize); // Reading fewer bytes than blockSize means we reached the end of the stream

        deflater.end();

        return compressedChunkLength;
    }

    /**
     * Decrypt and decompress the CaRT formatted data. The footer is also read.
     *
     * @param inputStream   Data to decrypt and decompress
     * @param outputStream  Decrypted and decompress data will be transferred to this output stream
     * @param decryptionKey Decryption key
     * @param startPosition start index in the input stream data of the encrypted and compressed file. This position
     *                      should be the index just after the header ends.
     * @return footer data
     * @throws CartException If any issues are encountered
     */
    private byte[] decryptAndDecompress(InputStream inputStream, OutputStream outputStream, SecretKeySpec decryptionKey,
                                        long startPosition) throws CartException {
        Inflater inflater = new Inflater();

        byte[] cryptChunk = new byte[blockSize];
        int readLength = 0;
        long position = startPosition;
        ByteArrayOutputStream footerStream = new ByteArrayOutputStream();
        Cipher cipher = InternalCartUtils.initCipher(decryptionKey);

        boolean bodyProcessed = false;
        // There are two break statements in the loop
        while (true) {
            readLength = readBytesFromStream(inputStream, cryptChunk);

            if (readLength <= 0) {
                break;
            }

            position += readLength;

            if (!bodyProcessed) {
                // Decrypt input data
                byte[] compressedChunk = cipher.update(cryptChunk, 0, readLength);
                inflater.setInput(compressedChunk, 0, readLength);
                byte[] inflateChunk = new byte[blockSize];
                // Closing a ByteArrayOutputStream is unnecessary.
                ByteArrayOutputStream rawOS = new ByteArrayOutputStream();

                // Decompress decrypted data
                try {
                    while (!inflater.needsInput() && !inflater.finished()) {
                        int count = inflater.inflate(inflateChunk);
                        rawOS.write(inflateChunk, 0, count);
                    }
                } catch (DataFormatException e) {
                    throw new CartException("Failed to decompress the data.", e);
                }

                // Saves the footer bytes read by copying them to the footer output stream
                if (inflater.finished()) {
                    int currentBlockExtra = (int) (position - startPosition - inflater.getBytesRead());
                    byte[] footerBytes = new byte[currentBlockExtra];
                    System.arraycopy(cryptChunk, readLength - currentBlockExtra, footerBytes, 0, currentBlockExtra);

                    writeToStream(footerStream, footerBytes);

                    bodyProcessed = true;
                }

                writeToStream(outputStream, rawOS.toByteArray());
            } else {
                footerStream.write(cryptChunk, 0, readLength);
            }

            // Why do we check if the inflater is finished?
            if (readLength < blockSize && inflater.finished()) {
                break;
            }
        }

        return footerStream.toByteArray();
    }

    @Override
    public FileMetadata getFileMetadata(File file, byte[] key) throws CartException {
        Preconditions.checkArgument(file != null, "File is null.");

        Header header;
        Footer footer;
        try (RandomAccessFile accessFile = new RandomAccessFile(file, "r");
             FileChannel channel = accessFile.getChannel()) {
            header = readHeader(channel, key);
            footer = readFooter(channel, header.getEncryptionKey(), file.length());
        } catch (FileNotFoundException e) {
            throw new CartException("File not found " + file.getPath(), e);
        } catch (IOException e) {
            throw new CartException("Failed to read the file " + file.getPath(), e);
        }

        return new FileMetadata(header.getOptionalHeader(), footer.getOptionalFooter());
    }

    /**
     * Read the entire header of a CaRT file
     *
     * @param channel FileChannel
     * @param key     decryption key
     * @return Header
     * @throws CartException If any issues are encountered
     */
    private Header readHeader(FileChannel channel, byte[] key) throws CartException {
        // Read mandatory header
        ByteBuffer buffer = ByteBuffer.allocate(CartUtils.MANDATORY_HEADER_LENGTH);
        int bytesRead = readBytesFromFileChannel(channel, buffer);
        buffer.flip();

        byte[] mandatoryHeaderBytes = new byte[bytesRead];
        buffer.get(mandatoryHeaderBytes, 0, bytesRead);

        Header header = Header.unpackMandatoryHeader(mandatoryHeaderBytes, BUILD_MAJOR);

        // Read optional header
        buffer = ByteBuffer.allocate((int) header.getOptionalHeaderLength());
        bytesRead = readBytesFromFileChannel(channel, buffer);

        buffer.flip();
        byte[] optionalHeaderBytes = new byte[bytesRead];
        buffer.get(optionalHeaderBytes, 0, bytesRead);
        byte[] headerBytes = Bytes.concat(mandatoryHeaderBytes, optionalHeaderBytes);

        return Header.unpackHeader(headerBytes, key, BUILD_MAJOR);
    }

    /**
     * Read the entire footer of a CaRT file, skipping the header and the encrypted / compressed file
     *
     * @param channel    FileChannel
     * @param key        decryption key
     * @param fileLength Length of the file
     * @return Footer
     * @throws CartException If any issues are encountered
     */
    private Footer readFooter(FileChannel channel, SecretKeySpec key, long fileLength) throws CartException {
        // Read mandatory footer
        ByteBuffer buffer = ByteBuffer.allocate(CartUtils.MANDATORY_FOOTER_LENGTH);
        long startPosition = fileLength - CartUtils.MANDATORY_FOOTER_LENGTH;
        int bytesRead = readBytesFromFileChannel(channel, buffer, startPosition);
        buffer.flip();

        byte[] mandatoryFooterBytes = new byte[bytesRead];
        buffer.get(mandatoryFooterBytes, 0, bytesRead);
        Footer footer = Footer.unpackMandatoryFooter(mandatoryFooterBytes);

        // Read optional footer
        long optionalFooterLength = footer.getOptionalFooterLength();
        long totalFooterLength = CartUtils.MANDATORY_FOOTER_LENGTH + optionalFooterLength;
        startPosition = fileLength - totalFooterLength;
        buffer = ByteBuffer.allocate((int) totalFooterLength);
        bytesRead = readBytesFromFileChannel(channel, buffer, startPosition);
        buffer.flip();

        byte[] footerBytes = new byte[bytesRead];
        buffer.get(footerBytes, 0, bytesRead);

        return Footer.unpackFooter(footerBytes, key);
    }

    /**
     * Reads a chunk of an {@link FileChannel} into a {@link ByteBuffer} and returns the number of bytes read.
     *
     * @param channel The FileChannel to read from
     * @param buffer  The ByteBuffer in which to store the read data.
     * @return The number of bytes read from the FileChannel
     * @throws CartException if an exception is thrown while reading from the channel
     */
    private int readBytesFromFileChannel(FileChannel channel, ByteBuffer buffer) throws CartException {
        try {
            return channel.read(buffer);
        } catch (IOException e) {
            throw new CartException("Failed to read from file channel.", e);
        }
    }

    /**
     * Reads a chunk of an {@link FileChannel} into a {@link ByteBuffer} and returns the number of bytes read.
     *
     * @param channel       The FileChannel to read from
     * @param buffer        The ByteBuffer in which to store the read data.
     * @param startPosition The position in the FileChannel to start reading from
     * @return The number of bytes read from the FileChannel
     * @throws CartException if an exception is thrown while reading from the channel
     */
    private int readBytesFromFileChannel(FileChannel channel, ByteBuffer buffer, long startPosition)
            throws CartException {
        try {
            return channel.read(buffer, startPosition);
        } catch (IOException e) {
            throw new CartException("Failed to read from file channel.", e);
        }
    }

    /**
     * Reads a chunk of an InputStream into a byte array and returns the number of bytes read.
     *
     * @param stream The InputStream to read from
     * @param buffer The byte array in which to store the read data.
     * @return The number of bytes read from the InputStream
     * @throws CartException if an exception is thrown while reading from the stream
     */
    private int readBytesFromStream(InputStream stream, byte[] buffer) throws CartException {
        try {
            return IOUtils.read(stream, buffer);
        } catch (IOException e) {
            throw new CartException("Failed to read from input stream.", e);
        }
    }

    /**
     * Writes a byte array to an OutputStream and wraps IOExceptions in CartExceptions.
     *
     * @param stream the OutputStream to write to
     * @param bytes  the byte array to write
     * @throws CartException if an exception is thrown while writing to the stream
     */
    private void writeToStream(OutputStream stream, byte[] bytes) throws CartException {
        try {
            stream.write(bytes);
        } catch (IOException e) {
            throw new CartException("Failed to write to the output stream.", e);
        }
    }
}
