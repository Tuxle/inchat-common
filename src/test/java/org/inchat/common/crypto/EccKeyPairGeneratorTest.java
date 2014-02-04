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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import static org.inchat.common.crypto.EccKeyPairGenerator.SEC_CURVE_NAME;
import static org.junit.Assert.*;
import org.junit.Test;

public class EccKeyPairGeneratorTest {

    private AsymmetricCipherKeyPair keyPair;

    @Test
    public void testGenerate() {
        keyPair = EccKeyPairGenerator.generate();
        assertNotNull(keyPair);
    }

    @Test
    public void testGenerateOnCurveName() {
        keyPair = EccKeyPairGenerator.generate();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECNamedCurveParameterSpec expectedParameterSpec = ECNamedCurveTable.getParameterSpec(SEC_CURVE_NAME);

        assertEquals(expectedParameterSpec.getG(), privateKey.getParameters().getG());
        assertEquals(expectedParameterSpec.getH(), privateKey.getParameters().getH());
        assertEquals(expectedParameterSpec.getN(), privateKey.getParameters().getN());
    }
}
