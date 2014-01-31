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

import java.util.UUID;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class ParticipantTest {

    private Participant participant;
    private UUID id;

    @Before
    public void setUp() {
        participant = new Participant();
        id = UUID.randomUUID();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetIdOnNull() {
        participant.setId(null);
    }

    @Test
    public void testSetId() {
        participant.setId(id);
        assertEquals(id, participant.id);
    }

    @Test
    public void testGetId() {
        participant.id = id;
        assertEquals(id, participant.getId());
    }

}
