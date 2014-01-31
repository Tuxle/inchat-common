/*
 * Copyright (C) 2013, 2014 inchat.org
 *
 * This file is part of inchat-common.
 *
 * inchat-common is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * inchat-common is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.inchat.common.crypto;

import java.security.KeyPair;
import java.security.Security;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class RsaOaepCipherTest {

    private final int KEY_PAIR_SIZE_IN_BITS = 2048;
    private RsaOaepCipher cipher;
    private byte[] privateKey;
    private byte[] publicKey;
    private boolean isPublicKeyForEncryption;
    private byte[] plaintext;
    private byte[] ciphertext;
    private byte[] output;

    @Before
    public void setUp() {
        plaintext = "this is a very long plaintext text that we want to encrypt and decrypt".getBytes();
        privateKey = "myPublicKey".getBytes();
        publicKey = "mySecretKey".getBytes();
        isPublicKeyForEncryption = true;

        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNulls() {
        cipher = new RsaOaepCipher(null, null, isPublicKeyForEncryption);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPrivateKey() {
        cipher = new RsaOaepCipher(null, publicKey, isPublicKeyForEncryption);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPublicKey() {
        cipher = new RsaOaepCipher(privateKey, null, isPublicKeyForEncryption);
    }

    @Test
    public void testConstructorOnArgumentAssignment() {
        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);
        assertSame(privateKey, cipher.privateKey);
        assertSame(publicKey, cipher.publicKey);
        assertEquals(isPublicKeyForEncryption, cipher.isPublicKeyForEncryption);

        isPublicKeyForEncryption = false;
        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);
        assertEquals(isPublicKeyForEncryption, cipher.isPublicKeyForEncryption);
    }

    @Test
    public void testConstructorOnCipherInit() {
        // The Bouncy Castle provider should not be installed yet.
        assertNull(Security.getProperty(BouncyCastleIntegrator.PROVIDER_NAME));

        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);

        // Now, the provider should be installed.
        assertNotNull(Security.getProvider(BouncyCastleIntegrator.PROVIDER_NAME));
        assertNotNull(cipher.cipher);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptOnNull() {
        output = cipher.encrypt(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptOnNull() {
        output = cipher.decrypt(null);
    }

    @Test
    public void testEncryptAndDecrypt() {
        intiCipherWithGeneratedKeyPair();

        // Encrypt
        ciphertext = cipher.encrypt(plaintext);
        assertNotNull(ciphertext);

        // Decrypt with the same, already initalized cipher
        output = cipher.decrypt(ciphertext);
        assertArrayEquals(plaintext, output);

        // Decrypt with a new cipher
        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);
        output = cipher.decrypt(ciphertext);
        assertArrayEquals(plaintext, output);
    }

    @Test
    public void testEncryptAndDecryptSeveralTextLengths() {
        int maximalRepeats = 10;
        intiCipherWithGeneratedKeyPair();

        for (int i = 0; i <= maximalRepeats; i++) {
            // Encrypt
            plaintext = generateStringByLength(i).getBytes();
            ciphertext = cipher.encrypt(plaintext);
            assertNotNull(ciphertext);

            // Decrypt with the same, already initalized cipher
            output = cipher.decrypt(ciphertext);
            assertArrayEquals(plaintext, output);
        }
    }

    private String generateStringByLength(int length) {
        String assembly = "";
        String charachter = "AAAAAAAAAAbbbbbbbbbbbbccccccccccccccddddddddddddddeeeeeeeeeeeeeeefffffffffffffff";

        for (int i = 0; i <= length; i++) {
            assembly += charachter;
        }

        return assembly;
    }

    private void intiCipherWithGeneratedKeyPair() {
        KeyPair keyPair = RsaKeyPairGenerator.generateKeyPair(KEY_PAIR_SIZE_IN_BITS);
        privateKey = keyPair.getPrivate().getEncoded();
        publicKey = keyPair.getPublic().getEncoded();
        cipher = new RsaOaepCipher(privateKey, publicKey, isPublicKeyForEncryption);
    }

}
