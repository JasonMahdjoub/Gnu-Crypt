/* DSSPrivateKey.java --
   Copyright 2001, 2002, 2003, 2006 Free Software Foundation, Inc.

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

package gnu.jgnu.security.key.dss;

import java.math.BigInteger;
import java.security.AccessController;

import gnu.jgnu.security.Registry;
import gnu.jgnu.security.action.GetPropertyAction;
import gnu.jgnu.security.key.IKeyPairCodec;
import gnu.vm.jgnu.security.PrivateKey;
import gnu.vm.jgnu.security.interfaces.DSAPrivateKey;

/**
 * An object that embodies a DSS (Digital Signature Standard) private key.
 *
 * @see #getEncoded
 */
public class DSSPrivateKey extends DSSKey implements PrivateKey, DSAPrivateKey {
	/**
	 * 
	 */
	private static final long serialVersionUID = -2956262548460971480L;

	/**
	 * A class method that takes the output of the <code>encodePrivateKey()</code>
	 * method of a DSS keypair codec object (an instance implementing
	 * {@link gnu.jgnu.security.key.IKeyPairCodec} for DSS keys, and re-constructs
	 * an instance of this object.
	 *
	 * @param k
	 *            the contents of a previously encoded instance of this object.
	 * @exception ArrayIndexOutOfBoundsException
	 *                if there is not enough bytes, in <code>k</code>, to represent
	 *                a valid encoding of an instance of this object.
	 * @exception IllegalArgumentException
	 *                if the byte sequence does not represent a valid encoding of an
	 *                instance of this object.
	 */
	public static DSSPrivateKey valueOf(byte[] k) {
		// try RAW codec
		if (k[0] == Registry.MAGIC_RAW_DSS_PRIVATE_KEY[0])
			try {
				return (DSSPrivateKey) new DSSKeyPairRawCodec().decodePrivateKey(k);
			} catch (IllegalArgumentException ignored) {
			}
		// try PKCS#8 codec
		return (DSSPrivateKey) new DSSKeyPairPKCS8Codec().decodePrivateKey(k);
	}

	/**
	 * A randomly or pseudorandomly generated integer with <code>0 &lt; x &lt;
	 * q</code>.
	 */
	private final BigInteger x;

	/** String representation of this key. Cached for speed. */
	private transient String str;

	/**
	 * Convenience constructor. Calls the constructor with 5 arguments passing
	 * {@link Registry#RAW_ENCODING_ID} as the identifier of the preferred encoding
	 * format.
	 *
	 * @param p
	 *            the public modulus.
	 * @param q
	 *            the public prime divisor of <code>p-1</code>.
	 * @param g
	 *            a generator of the unique cyclic group <code>Z<sup>*</sup>
	 *          <sub>p</sub></code>.
	 * @param x
	 *            the private key part.
	 */
	public DSSPrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
		this(Registry.RAW_ENCODING_ID, p, q, g, x);
	}

	/**
	 * Constructs a new instance of a <code>DSSPrivateKey</code> given the
	 * designated arguments.
	 *
	 * @param preferredFormat
	 *            the indetifier of the preferred encoding format to use when
	 *            externalizing this key.
	 * @param p
	 *            the public modulus.
	 * @param q
	 *            the public prime divisor of <code>p-1</code>.
	 * @param g
	 *            a generator of the unique cyclic group <code>Z<sup>*</sup>
	 *          <sub>p</sub></code>.
	 * @param x
	 *            the private key part.
	 */
	public DSSPrivateKey(int preferredFormat, BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
		super(preferredFormat == Registry.ASN1_ENCODING_ID ? Registry.PKCS8_ENCODING_ID : preferredFormat, p, q, g);
		this.x = x;
	}

	/**
	 * Returns <code>true</code> if the designated object is an instance of
	 * {@link DSAPrivateKey} and has the same DSS (Digital Signature Standard)
	 * parameter values as this one.
	 *
	 * @param obj
	 *            the other non-null DSS key to compare to.
	 * @return <code>true</code> if the designated object is of the same type and
	 *         value as this one.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!(obj instanceof DSAPrivateKey))
			return false;

		DSAPrivateKey that = (DSAPrivateKey) obj;
		return super.equals(that) && x.equals(that.getX());
	}

	/**
	 * Returns the encoded form of this private key according to the designated
	 * format.
	 *
	 * @param format
	 *            the desired format identifier of the resulting encoding.
	 * @return the byte sequence encoding this key according to the designated
	 *         format.
	 * @exception IllegalArgumentException
	 *                if the format is not supported.
	 * @see DSSKeyPairRawCodec
	 */
	@Override
	public byte[] getEncoded(int format) {
		byte[] result;
		switch (format) {
		case IKeyPairCodec.RAW_FORMAT:
			result = new DSSKeyPairRawCodec().encodePrivateKey(this);
			break;
		case IKeyPairCodec.PKCS8_FORMAT:
			result = new DSSKeyPairPKCS8Codec().encodePrivateKey(this);
			break;
		default:
			throw new IllegalArgumentException("Unsupported encoding format: " + format);
		}
		return result;
	}

	@Override
	public BigInteger getX() {
		return x;
	}

	@Override
	public String toString() {
		if (str == null) {
			String ls = AccessController.doPrivileged(new GetPropertyAction("line.separator"));
			str = new StringBuilder(this.getClass().getName()).append("(").append(super.toString()).append(",")
					.append(ls).append("x=0x").append("**...*").append(ls).append(")").toString();
		}
		return str;
	}
}
