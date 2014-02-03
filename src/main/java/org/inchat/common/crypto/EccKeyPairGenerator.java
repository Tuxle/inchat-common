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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class EccKeyPairGenerator {

    public static KeyPair generate() {
        BouncyCastleIntegrator.initBouncyCastleProvider();

        try {
            ECGenParameterSpec parameters = new ECGenParameterSpec(EccCipher.CURVE_NAME);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(EccCipher.ALGORITHM_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            generator.initialize(parameters, new SecureRandom());
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            throw new IllegalStateException("Could not generate a ECC key pair: " + ex.getMessage());
        }
    }

}
