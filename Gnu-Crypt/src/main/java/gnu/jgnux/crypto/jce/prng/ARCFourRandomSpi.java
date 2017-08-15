/* ARCFourRandomSpi.java --
   Copyright (C) 2002, 2003, 2006  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */

package gnu.jgnux.crypto.jce.prng;

import java.security.SecureRandomSpi;
import java.util.HashMap;

import gnu.jgnu.security.Registry;
import gnu.jgnu.security.jce.prng.SecureRandomAdapter;
import gnu.jgnu.security.prng.IRandom;
import gnu.jgnu.security.prng.LimitReachedException;
import gnu.jgnux.crypto.prng.ARCFour;
import gnu.jgnux.crypto.prng.PRNGFactory;

/**
 * Implementation of the <i>Service Provider Interface</i> (<b>SPI</b>) for the
 * ARCFOUR keystream generator.
 */
public class ARCFourRandomSpi extends SecureRandomSpi {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8580069890977866839L;

	/** Our underlying prng instance. */
	private IRandom adaptee;

	/** Have we been initialized? */
	private boolean virgin;

	/**
	 * Default 0-arguments constructor.
	 */
	public ARCFourRandomSpi() {
		super();
		adaptee = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);
		virgin = true;
	}

	@Override
	public byte[] engineGenerateSeed(int numBytes) {
		return SecureRandomAdapter.getSeed(numBytes);
	}

	@Override
	public void engineNextBytes(byte[] bytes) {
		if (virgin)
			this.engineSetSeed(engineGenerateSeed(32));
		try {
			adaptee.nextBytes(bytes, 0, bytes.length);
		} catch (LimitReachedException ignored) {
		}
	}

	@Override
	public void engineSetSeed(byte[] seed) {
		HashMap<Object, Object> attributes = new HashMap<>();
		attributes.put(ARCFour.ARCFOUR_KEY_MATERIAL, seed);
		adaptee.init(attributes);
		virgin = false;
	}
}
