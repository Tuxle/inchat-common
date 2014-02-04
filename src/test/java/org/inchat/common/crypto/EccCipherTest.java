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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

public class EccCipherTest {

    private final int NUMBER_OF_ENCRYPTIONS = 50;
    private EccCipher cipher;
    private AsymmetricCipherKeyPair localKeyPair;
    private AsymmetricCipherKeyPair remoteKeyPair;

    @Before
    public void setUp() {
        localKeyPair = EccKeyPairGenerator.generate();
        remoteKeyPair = EccKeyPairGenerator.generate();

        cipher = new EccCipher(localKeyPair, remoteKeyPair);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNulls() {
        cipher = new EccCipher(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPrivateKey() {
        cipher = new EccCipher(null, remoteKeyPair);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNullPublicKey() {
        cipher = new EccCipher(localKeyPair, null);
    }

    @Test
    public void testConstructorOnAllocation() {
        assertEquals(localKeyPair, cipher.localKeyPair);
        assertEquals(remoteKeyPair, cipher.remoteKeyPair);
    }

    @Test
    public void testConstructorOnCreatingCipher() {
        assertNotNull(cipher.iesEngine);
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

            output = cipher.decrypt(ciphertext);
            assertArrayEquals(plaintext, output);

            workingText += textAddition + textAddition;
        }
    }

}
