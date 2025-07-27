package org.weyland.starter.hw4.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class TokenEncryptionService {

    @Value("${token.encryption.key}")
    private String encryptionKey;

    /**
     * Создает JWE токен с заданными claims
     */
    public String createJwe(String subject, Map<String, Object> claims) {
        try {
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A192GCM)
                    .contentType("JWT")
                    .build();

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString());

            claims.forEach(claimsBuilder::claim);

            JWTClaimsSet claimsSet = claimsBuilder.build();

            EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

            SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            JWEEncrypter encrypter = new DirectEncrypter(key);
            jwt.encrypt(encrypter);

            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error creating JWE token", e);
        }
    }

    public JWTClaimsSet parseJwe(String jweString) {
        try {
            EncryptedJWT jwt = EncryptedJWT.parse(jweString);

            SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            JWEDecrypter decrypter = new DirectDecrypter(key);
            jwt.decrypt(decrypter);

            return jwt.getJWTClaimsSet();

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Error parsing JWE token", e);
        }
    }

    public boolean validateJwe(String jweString) {
        try {
            EncryptedJWT jwt = EncryptedJWT.parse(jweString);

            SecretKey key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            JWEDecrypter decrypter = new DirectDecrypter(key);
            jwt.decrypt(decrypter);

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
