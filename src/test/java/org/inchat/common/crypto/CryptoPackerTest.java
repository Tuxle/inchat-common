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

import org.inchat.common.Message;
import org.inchat.common.Participant;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Ignore;

public class CryptoPackerTest {

    private CryptoPacker localPacker;
    private CryptoPacker remotePacker;
    private Participant localParticipant;
    private Participant reomteParticipant;
    private Message plaintext;
    private byte[] ciphertext;

    @Before
    public void setUp() {
        localParticipant = new Participant(ParticipantIdGenerator.generateId());
        localParticipant.setKeyPair(EccKeyPairGenerator.generate());

        reomteParticipant = new Participant(ParticipantIdGenerator.generateId());
        reomteParticipant.setKeyPair(EccKeyPairGenerator.generate());

        plaintext = new Message();
        plaintext.setVersion("1.0");
        plaintext.setParticipant(localParticipant);
        plaintext.setInitializationVector(AesKeyGenerator.generateInitializationVector());
        plaintext.setKey(AesKeyGenerator.generateKey(CryptoPacker.SYMMETRIC_KEY_LENGTH_IN_BYTES));
        plaintext.setContent("hello world".getBytes());

        localPacker = new CryptoPacker(localParticipant);
        remotePacker = new CryptoPacker(reomteParticipant);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorOnNull() {
        localPacker = new CryptoPacker(null);
    }

    @Test
    public void testConstructorOnAssignment() {
        localPacker = new CryptoPacker(localParticipant);
        assertSame(localParticipant, localPacker.localParticipant);
        assertNotNull(localPacker.messagePack);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPackAndEncryptOnNull() {
        localPacker.packAndEncrypt(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPackAndEncryptOnNotSetParticipant() {
        plaintext = new Message();
        localPacker.packAndEncrypt(plaintext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPackAndEncryptOnParticipantMissingKeyPair() {
        plaintext.setParticipant(new Participant(ParticipantIdGenerator.generateId()));
        localPacker.packAndEncrypt(plaintext);
    }

    @Test
    public void testPackAndEncryptOnParticipant() {
        plaintext.setParticipant(localParticipant);
        localPacker.packAndEncrypt(plaintext);
    }

    @Test
    public void testPackAndEncryptOnCipherInit() {
        localPacker.packAndEncrypt(plaintext);

        assertEquals(AesKeyGenerator.IV_LENGTH_IN_BYTES,
                localPacker.plaintext.getInitializationVector().length);
        assertEquals(CryptoPacker.SYMMETRIC_KEY_LENGTH_IN_BYTES,
                localPacker.plaintext.getKey().length);

        assertArrayEquals(localPacker.plaintext.getInitializationVector(),
                localPacker.aesCipher.parameters.getIV());
    }

    /**
     * Ignored since there is a problem with the EccCipher.
     */
    @Ignore
    @Test
    public void testPackAndEncryptAndAlsoDecryptAndUnpack() {
        int minimalExpectedLenghtForThisMessageInBytes = 200;

        ciphertext = localPacker.packAndEncrypt(plaintext);
        assertTrue(ciphertext.length > minimalExpectedLenghtForThisMessageInBytes);

        Message decryptedCiphertext = remotePacker.decryptAndUnpack(ciphertext, localParticipant);
        assertEquals(plaintext.getVersion(), decryptedCiphertext.getVersion());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptAndUnPackOnNull() {
        localPacker.decryptAndUnpack(null, reomteParticipant);
    }

}
