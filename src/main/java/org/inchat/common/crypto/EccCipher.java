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
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;

/**
 * This {@link Cipher} allows to encrypt and decrypt data asymmetrically using
 * Elliptic Curve Cryptography (ECC).
 */
public class EccCipher implements Cipher {

    AsymmetricCipherKeyPair localKeyPair;
    AsymmetricCipherKeyPair remoteKeyPair;
    IESEngine iesEngine;
    IESParameters iesParameters;
    boolean isForEncryption;

    /**
     * Initializes the cipher with the given key pairs. To decrypt the
     * {@code localKeyPair} has to contain the private key. To encrypt for the
     * remote user, the {@code remoteKeyPair} has to contain at least the public
     * key.
     *
     * @param localKeyPair The key pair of the local participant. This may not
     * be null.
     * @param remoteKeyPair The key pair of the remote participant. This may not
     * be null.
     * @throws IllegalArgumentException If the arguments are null.
     */
    public EccCipher(AsymmetricCipherKeyPair localKeyPair, AsymmetricCipherKeyPair remoteKeyPair) {
        if (localKeyPair == null || remoteKeyPair == null) {
            throw new IllegalArgumentException("The arguments may not be null.");
        }

        this.localKeyPair = localKeyPair;
        this.remoteKeyPair = remoteKeyPair;

        initCipher();
    }

    private void initCipher() {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
        int cipherBlockSizeInBits = cipher.getBlockSize() * 8;

        HMac hmac = new HMac(new SHA256Digest());
        int hmacBlockSizeInBits = hmac.getMacSize() * 8;

        iesEngine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()), hmac, cipher);
        iesParameters = new IESWithCipherParameters(null, null, hmacBlockSizeInBits, cipherBlockSizeInBits);
    }

    /**
     * Encrypts the given plaintext with the initialized public key of the
     * remote user and the private key of the local user.
     *
     * @param plaintext The plaintext to encrypt, may not be null.
     * @return The ciphertext.
     * @throws IllegalArgumentException If the argument is null.
     * @throws EncryptionException If something goes wrong during encryption.
     */
    @Override
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        isForEncryption = true;
        iesEngine.init(isForEncryption, localKeyPair.getPrivate(), remoteKeyPair.getPublic(), iesParameters);

        try {
            return iesEngine.processBlock(plaintext, 0, plaintext.length);
        } catch (InvalidCipherTextException ex) {
            throw new EncryptionException("Could not encrypt the given plaintext: " + ex.getMessage());
        }
    }

    /**
     * Decrypts the given ciphertext with the initialized private key of the
     * local user and the public key of the remote user.
     *
     * @param ciphertext The ciphertext to decrypt, may not be null.
     * @return The plaintext.
     * @throws IllegalArgumentException If the argument is null.
     * @throws DecryptionException If something goes wrong during decryption.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        isForEncryption = false;
        iesEngine.init(isForEncryption, localKeyPair.getPrivate(), remoteKeyPair.getPublic(), iesParameters);

        try {
            return iesEngine.processBlock(ciphertext, 0, ciphertext.length);
        } catch (InvalidCipherTextException ex) {
            throw new DecryptionException("Could not decrypt the given ciphertext: " + ex.getMessage());
        }
    }
}
