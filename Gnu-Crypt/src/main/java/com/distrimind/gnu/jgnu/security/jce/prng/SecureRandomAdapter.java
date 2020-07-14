/* SecureRandomAdapter.java --
   Copyright (C) 2001, 2002, 2003, 2006 Free Software Foundation, Inc.

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

package com.distrimind.gnu.jgnu.security.jce.prng;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessController;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.distrimind.gnu.jgnu.security.action.GetSecurityPropertyAction;
import com.distrimind.gnu.jgnu.security.prng.LimitReachedException;
import com.distrimind.gnu.jgnu.security.prng.MDGenerator;
import com.distrimind.gnu.vm.jgnu.security.SecureRandom;
import com.distrimind.gnu.vm.jgnu.security.SecureRandomSpi;

/**
 * <p>
 * The implementation of a generic {@link com.distrimind.gnu.vm.jgnu.security.SecureRandom}
 * adapter class to wrap com.distrimind.gnu.crypto prng instances based on Message Digest
 * algorithms.
 * </p>
 *
 * <p>
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>) for the
 * {@link com.distrimind.gnu.vm.jgnu.security.SecureRandom} class, which provides the
 * functionality of a cryptographically strong pseudo-random number generator.
 * </p>
 *
 * <p>
 * All the abstract methods in the {@link SecureRandomSpi} class are implemented
 * by this class and all its sub-classes.
 * </p>
 */
public abstract class SecureRandomAdapter implements SecureRandomSpi {

	/**
	 * 
	 */
	private static final long serialVersionUID = 999603727925481878L;

	/** The name of the message digest algorithm used by the adaptee. */
	// private String mdName;

	private static final Logger logger = Logger.getLogger(SecureRandom.class.getName());

	private static final String SECURERANDOM_SOURCE = "securerandom.source";

	private static final String JAVA_SECURITY_EGD = "java.security.egd";

	public static final byte[] getSeed(int numBytes) {
		URL sourceUrl = null;
		String urlStr = null;

		byte[] buffer = new byte[numBytes];

		GetSecurityPropertyAction action = new GetSecurityPropertyAction(SECURERANDOM_SOURCE);
		try {
			urlStr = AccessController.doPrivileged(action);

			if (urlStr != null)
				sourceUrl = new URL(urlStr);
		} catch (MalformedURLException ignored) {
			logger.log(Level.WARNING, SECURERANDOM_SOURCE + " property is malformed: {0}", urlStr);
		}
		if (sourceUrl == null) {
			try {
				urlStr = System.getProperty(JAVA_SECURITY_EGD);
				if (urlStr != null)
					sourceUrl = new URL(urlStr);
			} catch (MalformedURLException mue) {
				logger.log(Level.WARNING, JAVA_SECURITY_EGD + " property is malformed: {0}", urlStr);
			}
		}
		if (sourceUrl != null) {

			try {
				File file = new File(sourceUrl.toURI());
				try (InputStream in = new FileInputStream(file)) {
					in.read(buffer);
					return buffer;
				}
				/*
				 * InputStream in = sourceUrl.openStream(); in.read(buffer); return buffer;
				 */
			} catch (IOException ioe) {
				logger.log(Level.FINE, "error reading random bytes", ioe);
			} catch (URISyntaxException e) {
			}
		}

		// If we get here, we did not get any seed from a property URL.
		VMSecureRandom.generateSeed(buffer, 0, buffer.length);
		return buffer;
	}

	private boolean isSeeded = false;

	/** Our underlying prng instance. */
	private MDGenerator adaptee = new MDGenerator();

	/**
	 * <p>
	 * Trivial protected constructor.
	 * </p>
	 *
	 * @param mdName
	 *            the canonical name of the underlying hash algorithm.
	 */
	protected SecureRandomAdapter(String mdName) {
		super();

		// this.mdName = mdName;
		adaptee.init(Collections.singletonMap((Object) MDGenerator.MD_NAME, mdName));
	}

	@Override
	public byte[] engineGenerateSeed(int numBytes) {
		return getSeed(numBytes);
	}

	@Override
	public void engineNextBytes(byte[] bytes) {
		if (!isSeeded) {
			engineSetSeed(engineGenerateSeed(32));
		}
		try {
			adaptee.nextBytes(bytes, 0, bytes.length);
		} catch (LimitReachedException ignored) {
		}
	}

	@Override
	public void engineSetSeed(byte[] seed) {
		adaptee.addRandomBytes(seed);
		isSeeded = true;
	}
}
