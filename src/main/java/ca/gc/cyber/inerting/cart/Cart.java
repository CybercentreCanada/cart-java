package ca.gc.cyber.inerting.cart;

import com.google.gson.JsonElement;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Public API of the CaRT file format.
 * <p>
 * CaRT means Compressed and RC4 Transport. The CaRT file format is used to store/transfer malware and it's associated
 * metadata. It neuters the malware so it cannot be executed and encrypt it so anti-virus softwares cannot flag the CaRT
 * file as malware.
 * <p>
 * The CaRT file format consists of the following blocks concatenated together:
 * <p>
 * Mandatory Header (38 bytes) CaRT has a mandatory header that looks like this
 *
 * <pre>
 *     4s      h        Q        16s         Q
 *    CART  VERSION  RESERVED  ARC4KEY  OPT_HEADER_LEN
 * </pre>
 * <p>
 * Where VERSION is 1 and RESERVED is 0. When the default key is used to decrypt the file, it is stored in the mandatory
 * header and is always the same thing (first 8 digit of pi twice). Otherwise, when a key is provided, the ARC4KEy is
 * filled with 0's, forcing the user to provide a key when unpacking.
 * <p>
 * Optional Header (OPT_HEADER_LEN bytes)
 * <p>
 * CaRT's optional header is a OPT_HEADER_LEN bytes RC4 blob of a json serialized header RC4(
 * JSON_SERIALIZED_OPTIONAL_HEADER)
 * <p>
 * Data block (N Bytes)
 * <p>
 * CaRT's data block is a zlib then RC4 block RC4(ZLIB(block encoded stream ))
 * <p>
 * Optional Footer (OPTIONAL_FOOTER_LEN bytes)
 * <p>
 * Like the optional header, CaRT's optional footer is a OPT_FOOTER_LEN bytes RC4 blob of a json serialized footer RC4(
 * JSON_SERIALIZED_OPTIONAL_FOOTER)
 * <p>
 * Mandatory Footer (32 Bytes)
 * <p>
 * CaRT ends its file with a mandatory footer which allow the format to read the footer and return the hashes without
 * reading the whole file
 *
 * <pre>
 *    4s      Q                    Q                  Q
 *   TRAC  RESERVED  OPT_FOOTER_START_POSITION  OPT_FOOTER_LEN
 * </pre>
 */
public interface Cart {

    /**
     * @return the version of this algorithm in the format 'CaRT v[major].[minor].[micro]'
     */
    String getVersion();

    /**
     * Compress and encrypt the data provided in the input stream and output the result into the given output stream.
     * The data will be prepended with a mandatory header. The data is also appended an optional footer, and the
     * mandatory footer.
     * <p>
     * The SHA-256, SHA-1, MD5 and the file length are calculated and stored in the optional footer, and also returned
     * in the {@link FileMetadata}.
     * <p>
     * The default key will be used to encrypt the data.
     *
     * @param inputStream  Input stream on the data
     * @param outputStream Output stream to write the resulting data to
     * @return {@link FileMetadata}
     * @throws CartException            If any issues are encountered during the transformation.
     * @throws IllegalArgumentException If the input stream or the output stream is null
     */
    FileMetadata pack(InputStream inputStream, OutputStream outputStream) throws CartException;

    /**
     * Compress and encrypt the data provided in the input stream and output the result into the given output stream.
     * The data will be prepended with a mandatory header. The data is also appended an optional footer, and the
     * mandatory footer.
     * <p>
     * The SHA-256, SHA-1, MD5 and the file length are calculated and stored in the optional footer, and also returned
     * in the {@link FileMetadata}.
     *
     * @param inputStream   Input stream on the data
     * @param outputStream  Output stream to write the resulting data to
     * @param encryptionKey Encryption key to use. User must remember their key in order to decrypt the file, since it
     *                      is not stored in the header. If null, a default encryption key will be used. This default
     *                      key is stored within the header. This key must be 16 bytes long.
     * @return {@link FileMetadata}
     * @throws CartException            If any issues are encountered during the transformation.
     * @throws IllegalArgumentException If the input stream or the output stream is null, or a key is provided but it is
     *                                  of the wrong length
     */
    FileMetadata pack(InputStream inputStream, OutputStream outputStream, byte[] encryptionKey) throws CartException;

    /**
     * Compress and encrypt the data provided in the input stream and output the result into the given output stream.
     * The data will be prepended with a mandatory header, and an optional header if present. The data is also appended
     * the optional footer if present, and the mandatory footer.
     * <p>
     * The SHA-256, SHA-1, MD5 and the file length are calculated and stored in the optional footer, and also returned
     * in the {@link FileMetadata}.
     * </p>
     *
     * @param inputStream    Input stream on the data
     * @param outputStream   Output stream to write the resulting data to
     * @param encryptionKey  Encryption key to use. User must remember their key in order to decrypt the file, since it
     *                       is not stored in the header. If null, a default encryption key will be used. This default
     *                       key is stored within the header. This key must be 16 bytes long.
     * @param optionalHeader Optional header that is prepended to the data if present. Set to null if there is none.
     * @param optionalFooter Optional footer to append to the data. If this is null, an optional footer will still be
     *                       created to hold the SHA-256, SSHA-1, MD5 and file length values. If present, these file
     *                       attributes will be added to the given footer.
     * @return {@link FileMetadata}
     * @throws CartException            If any issues are encountered during the transformation.
     * @throws IllegalArgumentException If the input stream or the output stream is null, or a key is provided but it is
     *                                  of the wrong length
     */
    FileMetadata pack(InputStream inputStream, OutputStream outputStream, byte[] encryptionKey,
                      JsonElement optionalHeader, JsonElement optionalFooter) throws CartException;

    /**
     * Decrypt and decompress the data in the input stream, writing the original file to the output stream, using the
     * default key found in the header as the decryption key.
     *
     * @param inputStream  Input stream on the data
     * @param outputStream Output stream to write the original file to
     * @return {@link FileMetadata}
     * @throws CartException            If the data in the input stream is not in CaRT format, or if any issues are
     *                                  encountered during the transformation.
     * @throws IllegalArgumentException If the input stream or the output stream is null
     */
    FileMetadata unpack(InputStream inputStream, OutputStream outputStream) throws CartException;

    /**
     * Decrypt and decompress the data in the input stream, writing the original file to the output stream.
     *
     * @param inputStream   Input stream on the data
     * @param outputStream  Output stream to write the original file to
     * @param decryptionKey Decryption key to use. If null, the default decryption key will be used. This default key is
     *                      found within the header. This key must be 16 bytes long.
     * @return {@link FileMetadata}
     * @throws CartException            If the data in the input stream is not in CaRT format, or if any issues are
     *                                  encountered during the transformation.
     * @throws IllegalArgumentException If the input stream or the output stream is null, or a key is provided but it is
     *                                  of the wrong length
     */
    FileMetadata unpack(InputStream inputStream, OutputStream outputStream, byte[] decryptionKey) throws CartException;

    /**
     * Return true if the input stream is for data already in CaRT format. The input stream is not closed, and is not
     * rewinded.
     *
     * @param inputStream InputStream
     * @param key         Decryption key
     * @return boolean
     */
    boolean isCart(InputStream inputStream, byte[] key);

    /**
     * If the input stream data represents is already in CaRT format, it will be unpacked. Otherwise, it will be
     * packed.
     *
     * @param inputStream    Input stream to pack or unpack
     * @param outputStream   Output stream where the resulting data will be transferred to
     * @param key            Key to encrypt or decrypt. If null, the default key will be used.
     * @param optionalHeader Optional header in JSON format. Can be null.
     * @param optionalFooter Optional footer in JSON format. Can be null.
     * @param filename       Name of the file to store in the header. Set it to null if no filename should be stored in
     *                       the header
     * @return {@link FileMetadata}
     * @throws CartException If any issues are encountered during the transformation.
     */
    FileMetadata cart(InputStream inputStream, OutputStream outputStream, byte[] key, JsonElement optionalHeader,
                      JsonElement optionalFooter, String filename) throws CartException;

    /**
     * Return the file metadata for the passed CaRT file.
     *
     * @param file          CaRT file
     * @param decryptionKey Decryption key
     * @return {@link FileMetadata}
     * @throws CartException If the file fails to parse
     */
    FileMetadata getFileMetadata(File file, byte[] decryptionKey) throws CartException;
}
