/*
 * JNKPU - Java Network Key Protector Unlocker (MS-NKPU)
 *
 * Copyright (C) 2017 Iain Price
 * Copyright (C) 2026 {AUTHOR}
 *
 * Unmodified from the original JNKPU.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */
package net.coagulate.JNKPU;

/** Represents a non terminal exception with the unlock.
 * Specifically, encapsulates all errors that cause us to be unable to process an unlock request, but that are not fatal and do not require us to terminate.
 * @author Iain Price
 */
public class UnlockException extends Exception {

    UnlockException(String message, Throwable cause) { super(message,cause); }
    UnlockException(String message) { super(message); }
}
