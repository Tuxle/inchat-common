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

import org.junit.Test;
import static org.junit.Assert.*;

public class AesKeyGeneratorTest {

    @Test
    public void testInstantiation() {
        AesKeyGenerator generator = new AesKeyGenerator();
    }

    @Test
    public void testGenerateKeyOnNegativeAndSmallLengths() {
        for (int i = -10; i < AesKeyGenerator.MINIMAL_KEY_LENGTH_IN_BYTES; i++) {
            try {
                AesKeyGenerator.generateKey(i);
            } catch (IllegalArgumentException ex) {
                continue;
            }
            fail("An AES key of the length of " + i + " bytes should lead to an IllegalArugmentException.");
        }
    }

    @Test
    public void testGenerateKeyOnValidLengths() {
        for (int i = AesKeyGenerator.MINIMAL_KEY_LENGTH_IN_BYTES; i < 2 * AesKeyGenerator.MINIMAL_KEY_LENGTH_IN_BYTES; i++) {
            try {
                byte[] output = AesKeyGenerator.generateKey(i);
                assertEquals(i, output.length);
            } catch (IllegalArgumentException ex) {
                fail("This key should be generatable, but the exception sais: " + ex.getMessage());
            }
        }
    }

    @Test
    public void testGenerateInitializationVectorOnValidLengths() {
        byte[] output = AesKeyGenerator.generateInitializationVector();
        assertEquals(AesKeyGenerator.IV_LENGTH_IN_BYTES, output.length);
    }

}
