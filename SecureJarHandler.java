package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

public class SecureJarHandler {

    public static SecretKey generateKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom());
        return keyGen.generateKey();
    }

    public static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    public static void writeFile(byte[] data, String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static void saveKey(SecretKey key, String path) throws IOException {
        byte[] encoded = key.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(encoded);
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(base64Key.getBytes());
        }
    }

    public static SecretKey loadKey(String path) throws IOException {
        byte[] encodedKey = Files.readAllBytes(Paths.get(path));
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static void main(String[] args) {
        try {
            String jarPath = "C://Users/fecur/Desktop/byte/test.jar";
            String encryptedPath = "C://Users/fecur/Desktop/byte/encrypted_file.dat";
            String keyPath = "C://Users/fecur/Desktop/byte/secret.key";
            String reEncryptedPath = "C://Users/fecur/Desktop/byte/re_encrypted_test.jar";

            SecretKey secretKey = generateKey(256);
            saveKey(secretKey, keyPath);

            byte[] jarBytes = readFile(jarPath);

            byte[] encryptedBytes = encrypt(jarBytes, secretKey);
            writeFile(encryptedBytes, encryptedPath);

            SecretKey loadedKey = loadKey(keyPath);
            byte[] decryptedBytes = decrypt(encryptedBytes, loadedKey);

            byte[] reEncryptedBytes = encrypt(decryptedBytes, loadedKey);
            writeFile(reEncryptedBytes, reEncryptedPath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
