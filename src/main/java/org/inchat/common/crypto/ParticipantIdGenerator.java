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

import java.security.SecureRandom;
import org.inchat.common.Participant;

/**
 * This class generates random {@link Participant} IDs.
 */
public class ParticipantIdGenerator {

    private final static int NUMBER_OF_RANDOM_BYTES = 500;

    /**
     * Returns a new {@link Participant} ID. Internally, an array of random
     * bytes were generated (using {@link SecureRandom}) and afterwards computed
     * as SHA-256 Digest.
     *
     * @return A new {@link Participant} ID.
     */
    public static byte[] generateId() {
        byte[] randomBytes = new byte[NUMBER_OF_RANDOM_BYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);

        return Digest.digestWithSha256(randomBytes);
    }

}
