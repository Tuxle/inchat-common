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
package org.inchat.common;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * Represents a instance in the network that does something with messages. For
 * example, a Participant could be a user or a server.
 */
public class Participant {

    public final static int ID_LENGTH_IN_BYTES = 256 / 8;

    byte[] id;
    AsymmetricCipherKeyPair keyPair;

    public Participant(byte[] id) {
        if (id == null || id.length != ID_LENGTH_IN_BYTES) {
            throw new IllegalArgumentException("The agument may not be null and it has to be exactly " + ID_LENGTH_IN_BYTES + " bytes in length.");
        }

        this.id = id;
    }

    public byte[] getId() {
        return id;
    }

    public void setKeyPair(AsymmetricCipherKeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.keyPair = keyPair;
    }

    public AsymmetricCipherKeyPair getKeyPair() {
        return keyPair;
    }
}
