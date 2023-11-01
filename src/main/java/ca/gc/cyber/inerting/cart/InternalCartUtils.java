package ca.gc.cyber.inerting.cart;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Constants and utilities shared among the classes within the cart package
 */
final class InternalCartUtils {

    /**
     * Name of the algorithm used for encryption and decryption
     */
    static final String ALGORITHM = "RC4";

    /**
     * Default constructor
     */
    private InternalCartUtils() {
    }

    /**
     * Initialize an instance of the Cipher to be used to encrypt and decrypt using the RC4 algorithm
     *
     * @param key Encryption / decryption key
     * @return Cipher
     * @throws CartException If the key is invalid, the algorithm is not supported, or the instance could not be created
     *                       for other reasons
     */
    static Cipher initCipher(SecretKeySpec key) throws CartException {

        try {
            Cipher cipher;
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new CartException("Failed to initialize the cipher instance.", e);
        }
    }

    /**
     * Return a new {@link JsonElement} that contains all the elements from the given {@link JsonElement} where the
     * {@link JsonObject}s are sorted by their property name.
     *
     * @param element {@link JsonElement} to sort
     * @return {@link JsonElement}
     */
    static JsonElement sortByKey(JsonElement element) {

        if (element == null) {
            return new JsonObject();
        } else {
            if (element.isJsonObject()) {
                JsonObject jsonObject = element.getAsJsonObject();

                Set<Map.Entry<String, JsonElement>> entrySet = jsonObject.entrySet();
                SortedMap<String, JsonElement> sorted = new TreeMap<>();
                for (Map.Entry<String, JsonElement> mapEntry : entrySet) {
                    sorted.put(mapEntry.getKey(), mapEntry.getValue());
                }

                JsonObject sortedJsonObject = new JsonObject();
                for (Map.Entry<String, JsonElement> mapEntry : sorted.entrySet()) {
                    sortedJsonObject.add(mapEntry.getKey(), sortByKey(mapEntry.getValue()));
                }

                return sortedJsonObject;
            } else if (element.isJsonArray()) {
                JsonArray array = element.getAsJsonArray();
                JsonArray newArray = new JsonArray();
                for (JsonElement arrayElement : array) {
                    newArray.add(sortByKey(arrayElement));
                }

                return newArray;
            } else {
                return element;
            }
        }
    }
}
