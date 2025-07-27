package org.weyland.starter.hw4.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class TokenEncryptionService {
    @Value("${token.encryption.key}")
    private String encryptionKey;

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private final SecureRandom secureRandom = new SecureRandom();

    public String encryptToken(String token) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            byte[] encryptedData = cipher.doFinal(token.getBytes());

            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedData);

            return ivBase64 + ":" + encryptedBase64;
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting token", e);
        }
    }

    public String decryptToken(String encryptedToken) {
        try {
            String[] parts = encryptedToken.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid token format");
            }

            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedData = Base64.getDecoder().decode(parts[1]);

            SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            String decryptedToken = new String(decryptedData);

            return decryptedToken;
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting token", e);
        }
    }
}
