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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;

/**
 * This {@link Cipher} allows to encrypt and decrypt data asymmetrically using
 * Elliptic Curve Cryptography (ECC). The primitive curve {@code secp384r1} (384
 * bit key size, equivalent to NIST's {@code P-384}, is used (regarding to: <a
 * href="http://www.bouncycastle.org/wiki/display/JA1/Supported+Curves+%28ECDSA+and+ECGOST%29">here</a>)).
 */
public class EccCipher implements Cipher {

    public final static String ALGORITHM_FAMILY_NAME = "EC";
    public final static String ALGORITHM_NAME = "ECIES";
    public final static String CURVE_NAME = "secp384r1";
    private final int MAC_KEY_SIZE = 128;
    javax.crypto.Cipher cipher;
    PrivateKey privateKey;
    PublicKey publicKey;
    IEKeySpec ieKeySpecification;
    IESParameterSpec iesParameterSpecification;

    /**
     * Initializes the cipher with the given private and public key. For more
     * information about this cipher, read its class javadoc.
     *
     * @param privateKey The private key to decrypt ciphertext, may not be null.
     * @param publicKey The public key to encrypt plaintext, may not be null.
     * @throws IllegalArgumentException If the arguments are null.
     * @throws IllegalStateException If the keys cannot be set up or the cipher
     * cannot be created correctly.
     */
    public EccCipher(byte[] privateKey, byte[] publicKey) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("The arguments may not be null.");
        }

        BouncyCastleIntegrator.initBouncyCastleProvider();
        createKeys(privateKey, publicKey);
        createCipher();
    }

    private void createKeys(byte[] privateKey, byte[] publicKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_FAMILY_NAME, BouncyCastleIntegrator.PROVIDER_NAME);

            this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new IllegalStateException("Could not create keys using the given byte arrays: " + ex.getMessage());
        }
    }

    private void createCipher() {
        try {
            cipher = javax.crypto.Cipher.getInstance(ALGORITHM_NAME, BouncyCastleIntegrator.PROVIDER_NAME);
            ieKeySpecification = new IEKeySpec(privateKey, publicKey);
            iesParameterSpecification = new IESParameterSpec(null, null, MAC_KEY_SIZE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            throw new IllegalStateException("Could not create the cipher for this curve: " + ex.getMessage());
        }
    }

    /**
     * Encrypts the given plaintext with the initialized public key.
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

        try {
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, ieKeySpecification, iesParameterSpecification);
            return cipher.doFinal(plaintext, 0, plaintext.length);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new EncryptionException("Could not encrypt the given plaintext: " + ex.getMessage());
        }
    }

    /**
     * Decrypts the given ciphertext with the initialized private key.
     *
     * @param ciphertext The cipher to decrypt, may not be null.
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
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, ieKeySpecification, iesParameterSpecification);
            return cipher.doFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            throw new DecryptionException("Could not decrypt the given plaintext: " + ex.getMessage());
        }
    }

}
