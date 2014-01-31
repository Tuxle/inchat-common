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

public class AesKeyGenerator {

    private final static String ALGORITHM_NAME = "AES";
    private final static int IV_LENGTH_IN_BYTES = 16;
    private final static int MINIMUM_KEY_LENGTH_IN_BYTES = 16;

    public static byte[] generateAesKey(int lengthInBytes) {
        if (lengthInBytes < MINIMUM_KEY_LENGTH_IN_BYTES) {
            throw new IllegalArgumentException("The length has to be at least " + MINIMUM_KEY_LENGTH_IN_BYTES + " bytes.");
        }

        try {
            BouncyCastleIntegrator.initBouncyCastleProvider();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            keyGenerator.init(lengthInBytes * 8);
            return keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new IllegalStateException("Could not generate key material: " + ex.getMessage());
        }
    }

    public static byte[] generateInitializationVector() {
        return generateAesKey(IV_LENGTH_IN_BYTES);
    }

}
