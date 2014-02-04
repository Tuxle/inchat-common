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

/**
 * A message contains all necessary information to transport the content to the
 * targeted participant. This also includes key material for the encryption and
 * decryption.
 */
public class Message {

    Participant participant;
    byte[] initializationVector;
    byte[] key;
    byte[] content;
    byte[] mac;

    /**
     * Sets the participant.
     *
     * @param participant
     * @throws IllegalArgumentException If the argument is null.
     */
    public void setParticipant(Participant participant) {
        if (participant == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.participant = participant;
    }

    public Participant getParticipant() {
        return participant;
    }

    /**
     * Sets the initialization vector (iv) as reference. The array is NOT
     * copied.
     *
     * @param iv
     * @throws IllegalArgumentException If the argument is null.
     */
    public void setInitializationVector(byte[] iv) {
        if (iv == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.initializationVector = iv;
    }

    public byte[] getInitializationVector() {
        return initializationVector;
    }

    /**
     * Sets the key as reference. The array is NOT copied.
     *
     * @param key
     * @throws IllegalArgumentException If the argument is null.
     */
    public void setKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.key = key;
    }

    public byte[] getKey() {
        return key;
    }

    /**
     * Sets the MAC as reference. The array is NOT copied.
     *
     * @param mac
     * @throws IllegalArgumentException If the argument is null.
     */
    public void setMac(byte[] mac) {
        if (mac == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.mac = mac;
    }

    public byte[] getMac() {
        return mac;
    }

    /**
     * Sets the content as reference. The array is NOT copied.
     *
     * @param content
     * @throws IllegalArgumentException If the argument is null.
     */
    public void setContent(byte[] content) {
        if (content == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.content = content;
    }

    public byte[] getContent() {
        return content;
    }
}
