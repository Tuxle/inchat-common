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
import org.bouncycastle.crypto.params.KeyParameter;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;

public class AesCbcCipherTest {

    private final byte[] CIPHERTEXT = new byte[]{(byte) 6, (byte) 73,
        (byte) -69, (byte) -28, (byte) -34, (byte) -41, (byte) 71, (byte) 114,
        (byte) 22, (byte) 30, (byte) -55, (byte) -16, (byte) 105, (byte) 7,
        (byte) 9, (byte) -58, (byte) -117, (byte) 76, (byte) 78, (byte) -91,
        (byte) -121, (byte) -58, (byte) 76, (byte) 114, (byte) -46, (byte) -115,
        (byte) 77, (byte) 42, (byte) 12, (byte) 117, (byte) -13, (byte) 94};
    private AesCbcCipher cipher;
    private AesCbcCipher initializedCipher;
    private byte[] plaintext;
    private byte[] initializationVector;
    private byte[] key;
    private byte[] output;

    @Before
    public void setUp() {
        plaintext = "this is the plaintext".getBytes();
        initializationVector = fillByteArray(16);
        key = fillByteArray(32);
        initializedCipher = new AesCbcCipher(initializationVector, key);
    }

    private byte[] fillByteArray(int length) {
        byte[] array = new byte[length];

        for (int i = 0; i < length; i++) {
            array[i] = (byte) i;
        }

        return array;
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNulls() {
        cipher = new AesCbcCipher(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullInitializationVector() {
        cipher = new AesCbcCipher(null, key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullKey() {
        cipher = new AesCbcCipher(initializationVector, null);
    }

    @Test
    public void testConstructorOnInitializationVectorLength() {
        int correctIvLength = 16;

        for (int i = 0; i < 20; i++) {
            try {
                cipher = new AesCbcCipher(fillByteArray(i), key);
                if (i != correctIvLength) {
                    fail("The IV of the length of " + i + " bytes should lead to an IllegalArgumentException.");
                }

            } catch (IllegalArgumentException ex) {
            }
        }

    }

    @Test
    public void testConstructorOnKeyLength() {
        int correctKeyLengths[] = {16, 24, 32};

        for (int i = 0; i < 50; i++) {
            try {
                cipher = new AesCbcCipher(initializationVector, fillByteArray(i));

                for (int length : correctKeyLengths) {
                    if (i == length) {
                        throw new IllegalArgumentException("Go 'manually' to the cacht block.");
                    }
                }

                fail("The key of the length of " + i + " bytes should lead to an IllegalArgumentException.");
            } catch (IllegalArgumentException ex) {
            }
        }
    }

    @Test
    public void testConstructorOnAssignments() {
        cipher = new AesCbcCipher(initializationVector, key);

        assertNotNull(cipher.parameters);
        assertArrayEquals(initializationVector, cipher.parameters.getIV());

        KeyParameter keyParameters = (KeyParameter) cipher.parameters.getParameters();
        assertArrayEquals(key, keyParameters.getKey());
    }

    @Test
    public void testConstructorOnCipherInit() {
        // The Bouncy Caste Provider should not be known now.
        assertNull(Security.getProperty(BouncyCastleIntegrator.PROVIDER_NAME));

        cipher = new AesCbcCipher(initializationVector, key);

        // Now, the Bouncy Castle Provider should be installed.
        assertNotNull(Security.getProvider(BouncyCastleIntegrator.PROVIDER_NAME));
        assertNotNull(cipher.cipher);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptOnNull() {
        output = initializedCipher.encrypt(null);
    }

    /**
     * This test checks if a specific plaintext (form {@code plaintext}) can be
     * encrypted to the exact same ciphertext. Of course, the same IV and Key
     * have to be used.
     */
    @Test
    public void testEncrypt() {
        output = initializedCipher.encrypt(plaintext);
        assertArrayEquals(CIPHERTEXT, output);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptOnNull() {
        output = initializedCipher.decrypt(null);
    }

    /**
     * This test checks if a specific ciphertext (form {@code CIPHERTEXT}) can
     * be decrypted to the exact same plaintext. Of course, the same IV and Key
     * have to be used.
     */
    @Test
    public void testDecrypt() {
        output = initializedCipher.decrypt(CIPHERTEXT);
        assertArrayEquals(plaintext, output);
    }

}
