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
import java.security.Security;
import org.junit.Test;
import static org.junit.Assert.*;

public class EccKeyPairGeneratorTest {

    private final static String EXPECTED_PRIVATE_KEY_FORMAT = "PKCS#8";
    private final static String EXPECTED_PUBLIC_KEY_FORMAT = "X.509";
    private final static int EXPECTED_PRIVATE_KEY_LENGTH_IN_BYTES = 194;
    private final static int EXPECTED_PUBLIC_KEY_LENGTH_IN_BYTES = 120;
    private KeyPair keyPair;

    @Test
    public void testGenerateOnBcProvider() {
        Security.removeProvider(BouncyCastleIntegrator.PROVIDER_NAME);

        keyPair = EccKeyPairGenerator.generate();
    }

    @Test
    public void testGenerateOnLenghts() {
        keyPair = EccKeyPairGenerator.generate();

        assertEquals(EXPECTED_PRIVATE_KEY_LENGTH_IN_BYTES, keyPair.getPrivate().getEncoded().length);
        assertEquals(EXPECTED_PUBLIC_KEY_LENGTH_IN_BYTES, keyPair.getPublic().getEncoded().length);
    }

    @Test
    public void testGenerateOnFormat() {
        keyPair = EccKeyPairGenerator.generate();

        assertEquals(EXPECTED_PRIVATE_KEY_FORMAT, keyPair.getPrivate().getFormat());
        assertEquals(EXPECTED_PUBLIC_KEY_FORMAT, keyPair.getPublic().getFormat());
    }

}
