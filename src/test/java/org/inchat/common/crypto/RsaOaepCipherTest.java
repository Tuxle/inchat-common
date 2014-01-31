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

import java.security.Security;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class RsaOaepCipherTest {

    private RsaOaepCipher cipher;
    private byte[] privateKey;
    private byte[] publicKey;
    private boolean isPublicKeyForEncryption;
    private byte[] plaintext;
    private byte[] ciphertext;
    private byte[] output;

    @Before
    public void setUp() {
        plaintext = "testtext".getBytes();

        privateKey = "myPulicKey".getBytes();
        publicKey = "mySecretsdfasdfaKey".getBytes();
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

    @Test
    public void testEncrypt() {
        output = cipher.encrypt(plaintext);
    }

}
