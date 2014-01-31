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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

/**
 * This {@link Cipher} encrypts and decrypts using the {@link RSAEngine} and
 * {@link OAEPEncoding}.
 */
public class RsaOaepCipher implements Cipher {

    AsymmetricBlockCipher cipher;
    AsymmetricKeyParameter parameters;
    byte[] privateKey;
    byte[] publicKey;
    boolean isPublicKeyForEncryption;

    /**
     * This Cipher can be used to asymmetrically encrypt and decrypt data.
     *
     * @param privateKey May not be null.
     * @param publicKey Many not be null.
     * @param isPublicKeyForEncryption Tells if the given public key is used for
     * encryption or decryption (encryption vs. signing).
     * @throws IllegalArgumentException If the arguments are null.
     */
    public RsaOaepCipher(byte[] privateKey, byte[] publicKey, boolean isPublicKeyForEncryption) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("The arguments may not be null.");
        }

        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.isPublicKeyForEncryption = isPublicKeyForEncryption;

        initCipher();
    }

    private void initCipher() {
        BouncyCastleIntegrator.initBouncyCastleProvider();
        cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest());
    }

    /**
     * Encrypts the given plaintext using the initialized key material.
     *
     * @param plaintext The plaintext to encrypt. This may not be null.
     * @return The ciphertext.
     * @throws IllegalArgumentException If the argument is null.
     * @throws EncryptionException If something goes wrong during encryption.
     */
    @Override
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        try {
            initCipherForEncryption(getEncryptionKey());
            return processCryptographicOperation(plaintext);
        } catch (IOException | InvalidCipherTextException ex) {
            throw new EncryptionException("Could not encrypt the plaintext: " + ex.getMessage());
        }
    }

    private void initCipherForEncryption(byte[] keyToUse) throws IOException {
        boolean isForEncryption = true;
        parameters = PublicKeyFactory.createKey(keyToUse);
        cipher.init(isForEncryption, parameters);
    }

    private byte[] getEncryptionKey() {
        return isPublicKeyForEncryption ? publicKey : privateKey;
    }

    /**
     * Decrypts the given ciphertext using the initialized key material.
     *
     * @param ciphertext The ciphertext to decrypt. This may not be null.
     * @return The plaintext.
     * @throws IllegalArgumentException If the argument is null.
     * @throws DecryptionException If something goes wrong during decryption.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        try {
            initCipherForDecryption(getDecryptionKey());
            return processCryptographicOperation(ciphertext);
        } catch (IOException | InvalidCipherTextException ex) {
            throw new DecryptionException("Could not decrypt the ciphertext: " + ex.getMessage());
        }
    }

    private void initCipherForDecryption(byte[] keyToUse) throws IOException {
        boolean isForEncryption = false;
        parameters = PrivateKeyFactory.createKey(keyToUse);
        cipher.init(isForEncryption, parameters);
    }

    private byte[] getDecryptionKey() {
        return isPublicKeyForEncryption ? privateKey : publicKey;
    }

    private byte[] processCryptographicOperation(byte[] toProcess) throws InvalidCipherTextException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] outputBuffer;
        int offset = 0;
        int processBlockLength = cipher.getInputBlockSize();

        while (offset < toProcess.length) {
            if (offset + processBlockLength > toProcess.length) {
                processBlockLength = toProcess.length - offset;
            }

            outputBuffer = cipher.processBlock(toProcess, offset, processBlockLength);
            outputStream.write(outputBuffer, 0, outputBuffer.length);
            offset += cipher.getInputBlockSize();
        }

        return outputStream.toByteArray();
    }

}
