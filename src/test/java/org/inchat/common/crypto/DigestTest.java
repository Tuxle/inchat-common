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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.util.encoders.Hex;
import org.inchat.common.Message;
import org.inchat.common.Participant;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class DigestTest {

    private final static String REFERENCE_DIGEST_PROVIDER = "SUN";
    private final static String HELLO_LOWER_CASE_AS_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    private byte[] bytePayload;
    private Message messagePayload;
    private byte[] output;

    @Before
    public void setUp() {
        bytePayload = "hello".getBytes();
        messagePayload = new Message();
    }

    @Test
    public void testInstantiation() {
        Digest digest = new Digest();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDigestWithSha256OnNull() {
        bytePayload = null;
        output = Digest.digestWithSha256(bytePayload);
    }

    @Test
    public void testDigestWithSha256OnBouncyCastleSetUp() {
        Security.removeProvider(BouncyCastleIntegrator.PROVIDER_NAME);

        output = Digest.digestWithSha256(bytePayload);

        assertNotNull(Security.getProvider(BouncyCastleIntegrator.PROVIDER_NAME));
    }

    @Test
    public void testDigestWithSha256OnPrecomputedDigest() {
        output = Digest.digestWithSha256(bytePayload);
        assertArrayEquals(Hex.decode(HELLO_LOWER_CASE_AS_SHA256), output);
    }

    @Test
    public void testDigestWithSha256() throws NoSuchAlgorithmException, NoSuchProviderException {
        String textAddition = "This Is A Very Long Text To Compute...";
        String payloadText = "";
        int rounds = 100;
        MessageDigest reference = MessageDigest.getInstance(Digest.SHA256_DIGEST_NAME, REFERENCE_DIGEST_PROVIDER);

        for (int i = 0; i < rounds; i++) {
            bytePayload = payloadText.getBytes();

            output = Digest.digestWithSha256(bytePayload);
            assertArrayEquals(reference.digest(bytePayload), output);

            payloadText += textAddition;
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDigestWithSha256ByMessageOnNull() {
        messagePayload = null;
        output = Digest.digestWithSha256(messagePayload);
    }

    @Test
    public void testDigestWithSha256ByMessageOnNotCompletelyFilledArgument() {
        try {
            output = Digest.digestWithSha256(messagePayload);
            fail("Exception should have been thrown.");
        } catch (IllegalArgumentException ex) {
        }

        try {
            messagePayload.setVersion("1");
            output = Digest.digestWithSha256(messagePayload);
            fail("Exception should have been thrown.");
        } catch (IllegalArgumentException ex) {
        }

        try {
            Participant filledParticipant = new Participant(ParticipantIdGenerator.generateId());
            messagePayload.setParticipant(filledParticipant);
            output = Digest.digestWithSha256(messagePayload);
            fail("Exception should have been thrown.");
        } catch (IllegalArgumentException ex) {
        }

        try {
            messagePayload.setInitializationVector(new byte[]{1, 2, 3});
            output = Digest.digestWithSha256(messagePayload);
            fail("Exception should have been thrown.");
        } catch (IllegalArgumentException ex) {
        }

        try {
            messagePayload.setKey(new byte[]{1, 2, 3});
            output = Digest.digestWithSha256(messagePayload);
            fail("Exception should have been thrown.");
        } catch (IllegalArgumentException ex) {
        }

        messagePayload.setContent(new byte[]{1, 2, 3});
        output = Digest.digestWithSha256(messagePayload); // nothing should be thrown here
    }

    @Test
    public void testDigestWithSha256ByMessage() {
        byte[] participantId = new byte[]{(byte) 104, (byte) 75, (byte) -86,
            (byte) -75, (byte) -19, (byte) -112, (byte) -90, (byte) -10,
            (byte) 10, (byte) -7, (byte) -114, (byte) 31, (byte) -113,
            (byte) -78, (byte) 29, (byte) -82, (byte) -14, (byte) -36,
            (byte) -89, (byte) -109, (byte) 118, (byte) 73, (byte) -12,
            (byte) 27, (byte) 12, (byte) -69, (byte) 36, (byte) -51,
            (byte) -79, (byte) -30, (byte) 89, (byte) 100};
        byte[] expectedDigest = new byte[]{(byte) 27, (byte) 34, (byte) -21,
            (byte) -113, (byte) 56, (byte) 1, (byte) -78, (byte) -23,
            (byte) -26, (byte) -64, (byte) 81, (byte) -12, (byte) 53,
            (byte) 93, (byte) 12, (byte) -115, (byte) -70, (byte) -90,
            (byte) 42, (byte) -121, (byte) -96, (byte) -21, (byte) -37,
            (byte) 126, (byte) -77, (byte) -90, (byte) -110, (byte) 117,
            (byte) 120, (byte) 6, (byte) -127, (byte) -37};

        messagePayload.setVersion("1.0");
        messagePayload.setParticipant(new Participant(participantId));
        messagePayload.setInitializationVector(new byte[]{1, 2, 3});
        messagePayload.setKey(new byte[]{4, 5, 6});
        messagePayload.setContent(new byte[]{7, 8, 9});

        output = Digest.digestWithSha256(messagePayload);

        assertArrayEquals(expectedDigest, output);
    }

}
