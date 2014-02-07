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

import org.inchat.common.crypto.ParticipantIdGenerator;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class MessageTest {

    private Message message;
    private String version;
    private Participant participant;
    private byte[] initializationVector;
    private byte[] key;
    private byte[] content;
    private byte[] mac;

    @Before
    public void setUp() {
        message = new Message();
        version = "1.2a";
        participant = new Participant(ParticipantIdGenerator.generateId());
        initializationVector = new byte[0];
        key = new byte[0];
        mac = new byte[0];
        content = new byte[0];
    }

    @Test
    public void testSetVersion() {
        message.setVersion(version);
        assertEquals(version, message.version);
    }

    @Test
    public void testGetVersion() {
        message.version = version;
        assertEquals(version, message.getVersion());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetParticipantOnNull() {
        message.setParticipant(null);
    }

    @Test
    public void testSetParticipant() {
        message.setParticipant(participant);
        assertSame(participant, message.participant);
    }

    @Test
    public void testGetParticipant() {
        message.participant = participant;
        assertSame(participant, message.getParticipant());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetInitializationVectorOnNull() {
        message.setInitializationVector(null);
    }

    @Test
    public void testSetInitializationVector() {
        message.setInitializationVector(initializationVector);
        assertSame(initializationVector, message.initializationVector);
    }

    @Test
    public void testGetInitializationVector() {
        message.initializationVector = initializationVector;
        assertSame(initializationVector, message.getInitializationVector());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetKeyOnNull() {
        message.setKey(null);
    }

    @Test
    public void testSetKey() {
        message.setKey(key);
        assertSame(key, message.key);
    }

    @Test
    public void testGetKey() {
        message.key = key;
        assertSame(key, message.getKey());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetMacOnNull() {
        message.setMac(null);
    }

    @Test
    public void testSetMac() {
        message.setMac(mac);
        assertSame(mac, message.mac);
    }

    @Test
    public void testGetMac() {
        message.mac = mac;
        assertSame(mac, message.getMac());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetContentOnNull() {
        message.setContent(null);
    }

    @Test
    public void testSetContent() {
        message.setContent(content);
        assertSame(content, message.content);
    }

    @Test
    public void testGetContent() {
        message.content = content;
        assertSame(content, message.getContent());
    }
}
