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

/**
 * This interface provides the primary methods for cryptographic operations.
 * It's implemented by {@link SymmetricCipher} and {@link AsymmetricCipher}.
 */
public interface Cipher {

    /**
     * Encrypts the given bytes. The key material has to be provided by the
     * concrete implementation.
     *
     * @param plaintext Not encrypted bytes.
     * @return Encrypted bytes (ciphertext).
     */
    public byte[] encrypt(byte[] plaintext);

    /**
     * Decrypts the given bytes. The key material has to be provided by the
     * concrete implementation.
     *
     * @param ciphertext Encrypted bytes.
     * @return Decrypted bytes (plaintext).
     */
    public byte[] decrypt(byte[] ciphertext);
}
