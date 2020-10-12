package org.keycloak.utils;

import org.junit.Test;
import org.keycloak.crypto.Aes128GcmEncryptor;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import static org.junit.Assert.assertEquals;

public class AesGcmEncryptorTest {

    @Test
    public void encrypt_decrypt() throws GeneralSecurityException {
        String login = "anton.brueckner";
        String secret = "e6a783cc-e1b5-4ca9-8057-c5e97d614762";
        byte[] encrypted = Aes128GcmEncryptor.encrypt(secret, login.getBytes(StandardCharsets.UTF_8));

        System.out.println(new String(encrypted));
        byte[] decrypted = Aes128GcmEncryptor.decrypt(secret, encrypted);
        System.out.println(new String(decrypted));
        assertEquals(login, new String(decrypted));
    }
}
