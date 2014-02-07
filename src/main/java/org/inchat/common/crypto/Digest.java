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
import org.inchat.common.Message;

/**
 * This class provides needed Digests.
 */
public class Digest {

    public final static String SHA256_DIGEST_NAME = "SHA-256";

    /**
     * Digests the given {@code payload} using the {@code SHA-256} hash
     * algorithm provided by Bouncy Castle.
     *
     * @param payload The payload to digest. This may not be null.
     * @return The calculated digest.
     * @throws IllegalArgumentException If the argument is null.
     * @throws IllegalStateException If the digest could not be set up.
     */
    public static byte[] digestWithSha256(byte[] payload) {
        if (payload == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        BouncyCastleIntegrator.initBouncyCastleProvider();

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(SHA256_DIGEST_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            return messageDigest.digest(payload);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new IllegalStateException("The digest could not be computed: " + ex.getMessage());
        }
    }

    /**
     * Digests certain fields of the given {@code payload}
     * <p>
     * The following fields are in this order concatenated into one byte array:
     * <ol>
     * <li>{@code version}</li>
     * <li>{@code participant.id}</li>
     * <li>{@code initializationVector}</li>
     * <li>{@code key}</li>
     * <li>{@code content}</li>
     * </ol>
     * The resulting byte array is used to calculate the digest.
     *
     * @param payload The message to digest, may not be null. The fields, as
     * listed above, have to be set.
     * @return The calculated digest.
     * @throws IllegalArgumentException If the requirements are not fulfilled.
     */
    public static byte[] digestWithSha256(Message payload) {
        if (payload == null
                || payload.getVersion() == null
                || payload.getVersion().isEmpty()
                || payload.getParticipant() == null
                || payload.getParticipant().getId() == null
                || payload.getInitializationVector() == null
                || payload.getInitializationVector().length == 0
                || payload.getKey() == null
                || payload.getKey().length == 0
                || payload.getContent() == null
                || payload.getContent().length == 0) {
            throw new IllegalArgumentException("The argument may not be null "
                    + "and it has to be correctly initialized.");
        }

        byte[] combinedFields = combineArrays(
                payload.getVersion().getBytes(),
                payload.getParticipant().getId(),
                payload.getInitializationVector(),
                payload.getKey(),
                payload.getContent());

        return digestWithSha256(combinedFields);
    }

    private static byte[] combineArrays(byte[] ... arrays) {
        int totalLength = 0;
        int offset = 0;

        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] combinedArray = new byte[totalLength];

        for (byte[] array : arrays) {
            System.arraycopy(array, 0, combinedArray, offset, array.length);
            offset += array.length;
        }

        return combinedArray;
    }
}
