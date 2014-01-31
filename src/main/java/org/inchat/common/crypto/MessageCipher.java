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

import org.inchat.common.Message;
import org.inchat.common.Participant;
import org.msgpack.MessagePack;

/**
 * A MessageCipher is used to encrypt and decrypt Messages. It uses internally
 * the {@link SymmetricCipher} and the {@link AsymmetricCipher} to do the actual
 * cryptographic work.
 */
public class MessageCipher {

    /**
     * Encrypts the given Message. It is encrypted using the public key of the
     * {@code decryptedMessage}'s {@link Participant} and the already
     * initialized key parameters of the {@link Message}.
     *
     * @param decryptedMessage The currently decrypted message to encrypt.
     * @return The encrypted {@link Message}, packed as {@link MessagePack} to
     * the inchat format.
     */
    public byte[] encrypt(Message decryptedMessage) {
        return null;
    }

    /**
     * Decrypts the given Message. It is decrypted using the private key of the
     * {@code encryptedMessage}'s {@link Participant} and the (originally
     * encrypted) key parameters of the {@link Message}.
     *
     * @param encryptedMessage The currently encrypted message to decrypt.
     * @return The decrypted {@link Message}.
     */
    public Message decrypt(byte[] encryptedMessage) {
        return null;
    }
}
