/* PKCS1_V1_5.java --
   Copyright (C) 2003, 2006, 2010 Free Software Foundation, Inc.

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

package gnu.jgnux.crypto.pad;

import gnu.jgnu.security.Registry;
import gnu.jgnu.security.sig.rsa.EME_PKCS1_V1_5;
import gnu.jgnu.security.util.PRNG;

/**
 * A padding algorithm implementation of the EME-PKCS1-V1.5 encoding/decoding
 * algorithm as described in section 7.2 of RFC-3447. This is effectively an
 * <i>Adapter</i> over an instance of {@link EME_PKCS1_V1_5} initialised with
 * the RSA public shared modulus length (in bytes).
 * <p>
 * References:
 * <ol>
 * <li><a href="http://www.ietf.org/rfc/rfc3447.txt">Public-Key Cryptography
 * Standards (PKCS) #1:</a><br>
 * RSA Cryptography Specifications Version 2.1.<br>
 * Jakob Jonsson and Burt Kaliski.</li>
 * </ol>
 *
 * @see EME_PKCS1_V1_5
 */
public class PKCS1_V1_5 extends BasePad {
	private EME_PKCS1_V1_5 codec;

	/**
	 * Trivial package-private constructor for use by the <i>Factory</i> class.
	 *
	 * @see PadFactory
	 */
	PKCS1_V1_5() {
		super(Registry.EME_PKCS1_V1_5_PAD);
	}

	@Override
	public byte[] pad(final byte[] in, final int offset, final int length) {
		final byte[] M = new byte[length];
		System.arraycopy(in, offset, M, 0, length);
		final byte[] EM = codec.encode(M);
		final byte[] result = new byte[blockSize - length];
		System.arraycopy(EM, 0, result, 0, result.length);
		return result;
	}

	@Override
	public boolean selfTest() {
		final int[] mLen = new int[] { 16, 20, 32, 48, 64 };
		final byte[] M = new byte[mLen[mLen.length - 1]];
		PRNG.getInstance().nextBytes(M);
		final byte[] EM = new byte[1024];
		byte[] p;
		int bs, i, j;
		for (bs = 256; bs < 1025; bs += 256) {
			init(bs);
			for (i = 0; i < mLen.length; i++) {
				j = mLen[i];
				p = pad(M, 0, j);
				if (j + p.length != blockSize) {
					return false;
				}
				System.arraycopy(p, 0, EM, 0, p.length);
				System.arraycopy(M, 0, EM, p.length, j);
				/*
				 * try {
				 */
				if (p.length != unpad(EM, 0, blockSize)) {
					return false;
				}
				/*
				 * } catch (WrongPaddingException x) { return false; }
				 */
			}
			reset();
		}
		return true;
	}

	@Override
	public void setup() {
		codec = EME_PKCS1_V1_5.getInstance(blockSize);
	}

	@Override
	public int unpad(final byte[] in, final int offset, final int length) {
		final byte[] EM = new byte[length];
		System.arraycopy(in, offset, EM, 0, length);
		final int result = length - codec.decode(EM).length;
		return result;
	}
}
