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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.KeyGenerator;

/**
 * This class generates AES keys and initialization vectors.
 */
public class AesKeyGenerator {

    public final static String ALGORITHM_NAME = "AES";
    public final static int IV_LENGTH_IN_BYTES = 16;
    public final static int MINIMAL_KEY_LENGTH_IN_BYTES = 16;

    /**
     * Generates a AES key.
     *
     * @param lengthInBytes Has to be at least 16 bytes.
     * @return The generated key.
     * @throws IllegalArgumentException If the {@code lengthInBytes} does not
     * fulfill the length requirements.
     * @throws IllegalStateException If something goes wrong during key
     * generation.
     */
    public static byte[] generateKey(int lengthInBytes) {
        if (lengthInBytes < MINIMAL_KEY_LENGTH_IN_BYTES) {
            throw new IllegalArgumentException("The length has to be at least " + MINIMAL_KEY_LENGTH_IN_BYTES + " bytes.");
        }

        BouncyCastleIntegrator.initBouncyCastleProvider();

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            keyGenerator.init(lengthInBytes * 8);
            return keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new IllegalStateException("Could not generate key material: " + ex.getMessage());
        }
    }

    /**
     * Generates initialization vectors for AES.
     *
     * @return The generated initialization vector.
     */
    public static byte[] generateInitializationVector() {
        return generateKey(IV_LENGTH_IN_BYTES);
    }
}
