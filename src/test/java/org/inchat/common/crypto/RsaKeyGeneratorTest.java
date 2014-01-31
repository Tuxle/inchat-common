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
import org.junit.Test;
import static org.junit.Assert.*;

public class RsaKeyGeneratorTest {

    @Test
    public void testGenerateKeysOnNegativeAndSmallKeySizes() {
        for (int i = -100; i < RsaKeyGenerator.MINIMAL_KEY_SIZE_IN_BITS; i++) {
            try {
                RsaKeyGenerator.generateKeys(i);
                fail("Keys with the size of " + i + " bits should not be generatable.");
            } catch (IllegalArgumentException ex) {
            }
        }
    }

    @Test
    public void testGenerateKeysOnValidSize() {
        KeyPair keyPair = RsaKeyGenerator.generateKeys(RsaKeyGenerator.MINIMAL_KEY_SIZE_IN_BITS);

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic().getEncoded());
        assertNotNull(keyPair.getPrivate().getEncoded());
    }

}
