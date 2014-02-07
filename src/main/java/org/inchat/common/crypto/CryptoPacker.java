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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.inchat.common.Message;
import org.inchat.common.MessageField;
import org.inchat.common.Participant;
import org.msgpack.MessagePack;
import org.msgpack.template.Template;
import org.msgpack.template.Templates;
import org.msgpack.unpacker.Unpacker;

/**
 * Allows to pack-and-encrypt and decrypt-and-unpack using
 * {@link EccCipher}, {@link AesCbcCipher} and {@link MessagePack}.
 */
public class CryptoPacker {

    public final static int SYMMETRIC_KEY_LENGTH_IN_BYTES = 256 / 8;
    MessagePack messagePack;
    Participant localParticipant;
    Message plaintext;
    EccCipher eccCipher;
    AesCbcCipher aesCipher;
    byte[] plaintextMac;
    byte[] packedParameters;
    byte[] packedContent;
    byte[] encryptedPackedParameters;
    byte[] encryptedPacketContent;
    byte[] ciphertext;

    /**
     * Instantiates a new {@link CryptoPacker} with the {@code localParticipant}
     * which contains key material for signing and decryption.
     *
     * @param localParticipant The local participant with key material. May not
     * be null.
     * @throws IllegalArgumentException If the argument is null.
     */
    public CryptoPacker(Participant localParticipant) {
        if (localParticipant == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.localParticipant = localParticipant;
        messagePack = new MessagePack();
    }

    /**
     * Packs and encrypts the given {@code plaintext} to a {@link MessagePack}
     * byte array.<p>
     * The following fields <b>will not be</b> encrypted:
     * <ul>
     * <li>Version: {@code VRS}</li>
     * <li>Participant: {@code PRT}</li>
     * </ul><p>
     * The following fields <b>will be</b> be encrypted:
     * <ul>
     * <li>Parameters: {@code PRM} with it's <i>inner Fields</i></li>
     * <ul>
     * <li>Initalization Vector for AES: {@code IV}</li>
     * <li>Key for AES: {@code KEY}</li>
     * <li>Initalization Vector: {@code iv}</li>
     * <li>MAC of defined attributes: {@code MAC}</li>
     * </ul>
     * <li>Content: {@code CNT}</li>
     * <ul>
     * <li>The effective message: {@code MSG}</li>
     * <li>All other fields in {@code CNT}</li>
     * </ul>
     * </ul>
     * The AES initialization vector and key
     * ({@code plaintext.initializationVector} respectively
     * {@code plaintext.key}) will be generated and set to {@code plaintext}.
     *
     * @param plaintext The unencrypted {@link Message}. This may not be null
     * and has to have a initialized {@link Participant} with key pair.
     * @return The messagePacked and encrypted message.
     * @throws IllegalArgumentException If the argument is null or it's
     * {@link Participant} is not set up correctly.
     * @throws PackerException If anything goes wrong during
     * packing/serializing.
     */
    public byte[] packAndEncrypt(Message plaintext) {
        validatePlaintext(plaintext);

        generateKeyAndInitCiphers();
        calculateMac();

        packParameterField();
        packContentField();

        encryptParameterFieldAsymmetrically();
        encryptContentFieldSymmetrically();
        packAllPartsToCiphertext();

        return ciphertext;
    }

    private void validatePlaintext(Message plaintext) {
        if (plaintext == null
                || plaintext.getParticipant() == null
                || plaintext.getParticipant().getKeyPair() == null) {
            throw new IllegalArgumentException("The argument may not be null and "
                    + "it has to have a Participant with a KeyPair that contains "
                    + "at least the public key.");
        }

        this.plaintext = plaintext;
    }

    private void generateKeyAndInitCiphers() {
        plaintext.setInitializationVector(AesKeyGenerator.generateInitializationVector());
        plaintext.setKey(AesKeyGenerator.generateKey(SYMMETRIC_KEY_LENGTH_IN_BYTES));
        aesCipher = new AesCbcCipher(plaintext.getInitializationVector(), plaintext.getKey());

        eccCipher = new EccCipher(localParticipant.getKeyPair(), plaintext.getParticipant().getKeyPair());
    }

    private void calculateMac() {
        plaintextMac = Digest.digestWithSha256(plaintext);
    }

    private void packParameterField() {
        Map<String, byte[]> map = new HashMap<>();

        map.put(MessageField.PRM_IV.toString(), plaintext.getInitializationVector());
        map.put(MessageField.PRM_KEY.toString(), plaintext.getKey());
        map.put(MessageField.PRM_MAC.toString(), plaintextMac);

        packedParameters = serializeMap(map);
    }

    private void packContentField() {
        Map<String, byte[]> map = new HashMap<>();
        map.put(MessageField.CNT_MSG.toString(), plaintext.getContent());

        packedContent = serializeMap(map);
    }

    private void encryptParameterFieldAsymmetrically() {
        encryptedPackedParameters = eccCipher.encrypt(packedParameters);
    }

    private void encryptContentFieldSymmetrically() {
        encryptedPacketContent = aesCipher.encrypt(plaintextMac);
    }

    private void packAllPartsToCiphertext() {
        Map<String, byte[]> map = new HashMap<>();

        map.put(MessageField.VRS.toString(), plaintext.getVersion().getBytes());
        map.put(MessageField.PRT.toString(), plaintext.getParticipant().getId());
        map.put(MessageField.PRM.toString(), encryptedPackedParameters);
        map.put(MessageField.CNT.toString(), encryptedPacketContent);

        ciphertext = serializeMap(map);
    }

    private byte[] serializeMap(Map<String, byte[]> map) {
        try {
            return messagePack.write(map);
        } catch (IOException ex) {
            throw new PackerException("Could not serialize a map to a MessagePack: " + ex.getMessage());
        }
    }

    /**
     * Decrypts and unpacks the given {@code ciphertext} to a {@link Message}.
     *
     * @param ciphertext The encrypted message, serialized using
     * {@link MessagePack}. This may not be null.
     * @param remotePartitipant The remote participant, required for it's public
     * key. This will be removed and is only temporary.
     * @return The plaintext message.
     * @throws IllegalArgumentException If the argument is null.
     * @throws PackerException If anything goes wrong during
     * unpacking/deserializing. Also, when the integrity of the message cannot
     * be verified.
     */
    public Message decryptAndUnpack(byte[] ciphertext, Participant remotePartitipant) {
        validateCiphertext(ciphertext);

        unpackAllPartsFromCiphertext();

        initAsymmetricCipher(remotePartitipant);
        decyptParameters();
        unpackParameters();

        initSymmetricCipher();
        decyptContent();
        unpackContent();

        verifyIntegrityViaDigestComparison();

        return plaintext;
    }

    private void validateCiphertext(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("The argument may not be null.");
        }

        this.ciphertext = ciphertext;
    }

    private void unpackAllPartsFromCiphertext() {
        Map<String, byte[]> map = buildMapFromBytes(ciphertext);

        plaintext = new Message();

        plaintext.setVersion(readStringFromMap(map, MessageField.VRS));
        plaintext.setParticipant(new Participant(readByteArrayFromMap(map, MessageField.PRT)));

        encryptedPackedParameters = readByteArrayFromMap(map, MessageField.PRM);
        encryptedPacketContent = readByteArrayFromMap(map, MessageField.CNT);
    }

    private void initAsymmetricCipher(Participant remotePartitipant) {
        eccCipher = new EccCipher(localParticipant.getKeyPair(), remotePartitipant.getKeyPair());
    }

    private void decyptParameters() {
        packedParameters = eccCipher.decrypt(encryptedPackedParameters);
    }

    private void unpackParameters() {
        Map<String, byte[]> map = buildMapFromBytes(packedParameters);

        plaintext.setInitializationVector(readByteArrayFromMap(map, MessageField.PRM_IV));
        plaintext.setKey(readByteArrayFromMap(map, MessageField.PRM_KEY));
        plaintext.setMac(readByteArrayFromMap(map, MessageField.PRM_MAC));
    }

    private void initSymmetricCipher() {
        aesCipher = new AesCbcCipher(plaintext.getInitializationVector(), plaintext.getKey());
    }

    private void decyptContent() {
        packedContent = eccCipher.decrypt(encryptedPacketContent);
    }

    private void unpackContent() {
        Map<String, byte[]> map = buildMapFromBytes(packedContent);

        plaintext.setContent(readByteArrayFromMap(map, MessageField.CNT_MSG));
    }

    private Map<String, byte[]> buildMapFromBytes(byte[] bytes) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);

        Unpacker unpacker = messagePack.createUnpacker(inputStream);
        Template<Map<String, byte[]>> mapTemplate = Templates.tMap(Templates.TString, Templates.TByteArray);

        try {
            return unpacker.read(mapTemplate);
        } catch (IOException ex) {
            throw new PackerException("Could not read from an unpacker: " + ex.getMessage());
        }
    }

    private String readStringFromMap(Map<String, byte[]> map, MessageField field) {
        return new String(readByteArrayFromMap(map, field));
    }

    private byte[] readByteArrayFromMap(Map<String, byte[]> map, MessageField field) {
        return map.get(field.toString());
    }

    public void verifyIntegrityViaDigestComparison() {
        plaintextMac = Digest.digestWithSha256(plaintext);

        if (!Arrays.equals(plaintextMac, plaintext.getMac())) {
            throw new PackerException("The given ciphertext could not be decrypted and unpacked  since the MACs do not match.");
        }

    }

}
