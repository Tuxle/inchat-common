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
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * This class generates key pairs for RSA. It uses {@link SecureRandom} as
 * entropy source.
 */
public class RsaKeyGenerator {

    public final static String ALGORITHM_NAME = "RSA";
    public final static int MINIMAL_KEY_SIZE_IN_BITS = 2048;

    /**
     * Generates a {@link KeyPair} of the given size. The {@code keySizeInBits}
     * has to be at lest 2048 bits.
     *
     * @param keySizeInBits The key size.
     * @return Generated KeyPair, ready for usage.
     * @throws IllegalArgumentException If the key size is smaller than
     * required.
     * @throws IllegalStateException If something goes wrong during generating
     * the keys.
     */
    public static KeyPair generateKeys(int keySizeInBits) {
        if (keySizeInBits < MINIMAL_KEY_SIZE_IN_BITS) {
            throw new IllegalArgumentException("The key size has to be at least " + MINIMAL_KEY_SIZE_IN_BITS + " bits.");
        }

        BouncyCastleIntegrator.initBouncyCastleProvider();

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            generator.initialize(keySizeInBits, random);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new IllegalStateException("Could not generate RSA Keys: " + ex.getMessage());
        }
    }
}
