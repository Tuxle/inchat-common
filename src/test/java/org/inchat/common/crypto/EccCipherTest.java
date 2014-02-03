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
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

public class EccCipherTest {
    private final String EXPECTED_IE_KEY_NAME = "IES";
    private final int EXPECTED_MAC_KEY_SIZE = 128;
    private final int NUMBER_OF_ENCRYPTIONS = 10;
    private final int EXPECTED_PLAINTEXT_CIPHERTEXT_DELTA_BYTES = 20;
    private EccCipher cipher;
    private byte[] privateKey;
    private byte[] publicKey;

    @Before
    public void setUp() {
        KeyPair keyPair = EccKeyPairGenerator.generate();
        privateKey = keyPair.getPrivate().getEncoded();
        publicKey = keyPair.getPublic().getEncoded();

        cipher = new EccCipher(privateKey, publicKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNulls() {
        cipher = new EccCipher(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPrivateKey() {
        cipher = new EccCipher(null, publicKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPublicKey() {
        cipher = new EccCipher(privateKey, null);
    }

    @Test
    public void testConstructorOnAllocation() {
        assertArrayEquals(privateKey, cipher.privateKey.getEncoded());
        assertArrayEquals(publicKey, cipher.publicKey.getEncoded());
    }

    @Test
    public void testConstructorOnCreatingCipher() {
         assertEquals(EXPECTED_IE_KEY_NAME, cipher.ieKeySpecification.getAlgorithm());
         assertEquals(EXPECTED_MAC_KEY_SIZE, cipher.iesParameterSpecification.getMacKeySize());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptOnNull() {
        cipher.encrypt(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptOnNull() {
        cipher.decrypt(null);
    }

    @Test
    public void testEncryptionAndDecryption() {
        String workingText = "";
        String textAddition = "Text_";
        byte[] plaintext;
        byte[] ciphertext;
        byte[] output;

        for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; i++) {
            plaintext = workingText.getBytes();

            ciphertext = cipher.encrypt(plaintext);
            assertThat(workingText, not(equalTo(new String(ciphertext))));
            assertEquals(EXPECTED_PLAINTEXT_CIPHERTEXT_DELTA_BYTES, ciphertext.length - plaintext.length);

            output = cipher.decrypt(ciphertext);
            assertArrayEquals(plaintext, output);

            workingText += textAddition + textAddition;
        }
    }

}
