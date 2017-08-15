/* RSACipherImpl.java --
   Copyright (C) 2005, 2006  Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

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
exception statement from your version. */

package gnu.jgnux.crypto;

import java.math.BigInteger;

import gnu.jgnu.security.sig.rsa.EME_PKCS1_V1_5;
import gnu.vm.jgnu.security.AlgorithmParameters;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.Key;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.SecureRandom;
import gnu.vm.jgnu.security.interfaces.RSAKey;
import gnu.vm.jgnu.security.interfaces.RSAPrivateCrtKey;
import gnu.vm.jgnu.security.interfaces.RSAPrivateKey;
import gnu.vm.jgnu.security.interfaces.RSAPublicKey;
import gnu.vm.jgnu.security.spec.AlgorithmParameterSpec;
import gnu.vm.jgnux.crypto.Cipher;
import gnu.vm.jgnux.crypto.CipherSpi;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.ShortBufferException;

public class RSACipherImpl extends CipherSpi {

	private static final byte[] EMPTY = new byte[0];

	private int opmode = -1;

	private RSAPrivateKey decipherKey = null;

	private RSAPublicKey blindingKey = null;

	private RSAPublicKey encipherKey = null;

	private SecureRandom random = null;

	private byte[] dataBuffer = null;

	private int pos = 0;

	protected int engineDoFinal(byte[] out, int offset) throws ShortBufferException, IllegalBlockSizeException {
		byte[] result = engineDoFinal(EMPTY, 0, 0);
		if (out.length - offset < result.length)
			throw new ShortBufferException("need " + result.length + ", have " + (out.length - offset));
		System.arraycopy(result, 0, out, offset, result.length);
		return result.length;
	}

	@Override
	protected byte[] engineDoFinal(byte[] in, int offset, int length) throws IllegalBlockSizeException {
		engineUpdate(in, offset, length);
		if (opmode == Cipher.DECRYPT_MODE) {
			BigInteger enc = new BigInteger(1, dataBuffer);
			byte[] dec = rsaDecrypt(enc);
			EME_PKCS1_V1_5 pkcs = EME_PKCS1_V1_5.getInstance(decipherKey);
			byte[] result = pkcs.decode(dec);
			return result;
		} else {
			offset = dataBuffer.length - pos;
			if (offset < 3)
				throw new IllegalBlockSizeException("input is too large to encrypt");
			EME_PKCS1_V1_5 pkcs = EME_PKCS1_V1_5.getInstance(encipherKey);
			if (random == null)
				random = new SecureRandom();
			byte[] em = new byte[pos];
			System.arraycopy(dataBuffer, 0, em, 0, pos);
			byte[] dec = pkcs.encode(em, random);
			BigInteger x = new BigInteger(1, dec);
			BigInteger y = x.modPow(encipherKey.getPublicExponent(), encipherKey.getModulus());
			byte[] enc = y.toByteArray();
			if (enc[0] == 0x00) {
				byte[] tmp = new byte[enc.length - 1];
				System.arraycopy(enc, 1, tmp, 0, tmp.length);
				enc = tmp;
			}
			pos = 0;
			return enc;
		}
	}

	@Override
	protected int engineDoFinal(final byte[] input, final int offset, final int length, final byte[] output,
			final int outputOffset) throws ShortBufferException, IllegalBlockSizeException {
		byte[] result = engineDoFinal(input, offset, length);
		if (output.length - outputOffset < result.length)
			throw new ShortBufferException("need " + result.length + ", have " + (output.length - outputOffset));
		System.arraycopy(result, 0, output, outputOffset, result.length);
		return result.length;
	}

	@Override
	protected int engineGetBlockSize() {
		return 1;
	}

	@Override
	protected byte[] engineGetIV() {
		return null;
	}

	@Override
	protected int engineGetKeySize(final Key key) throws InvalidKeyException {
		if (!(key instanceof RSAKey))
			throw new InvalidKeyException("not an RSA key");
		return ((RSAKey) key).getModulus().bitLength();
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		int outputLen = 0;
		if (decipherKey != null)
			outputLen = (decipherKey.getModulus().bitLength() + 7) / 8;
		else if (encipherKey != null)
			outputLen = (encipherKey.getModulus().bitLength() + 7) / 8;
		else
			throw new IllegalStateException("not initialized");
		if (inputLen > outputLen)
			throw new IllegalArgumentException("not configured to encode " + inputLen + "bytes; at most " + outputLen);
		return outputLen;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException {
		engineInit(opmode, key, random);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec spec, SecureRandom random)
			throws InvalidKeyException {
		engineInit(opmode, key, random);
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		int outputLen = 0;
		if (opmode == Cipher.ENCRYPT_MODE) {
			if (!(key instanceof RSAPublicKey))
				throw new InvalidKeyException("expecting a RSAPublicKey");
			encipherKey = (RSAPublicKey) key;
			decipherKey = null;
			blindingKey = null;
			outputLen = (encipherKey.getModulus().bitLength() + 7) / 8;
		} else if (opmode == Cipher.DECRYPT_MODE) {
			if (key instanceof RSAPrivateKey) {
				decipherKey = (RSAPrivateKey) key;
				encipherKey = null;
				blindingKey = null;
				outputLen = (decipherKey.getModulus().bitLength() + 7) / 8;
			} else if (key instanceof RSAPublicKey) {
				if (decipherKey == null)
					throw new IllegalStateException("must configure decryption key first");
				if (!decipherKey.getModulus().equals(((RSAPublicKey) key).getModulus()))
					throw new InvalidKeyException("blinding key is not compatible");
				blindingKey = (RSAPublicKey) key;
				return;
			} else
				throw new InvalidKeyException("expecting either an RSAPrivateKey or an RSAPublicKey (for blinding)");
		} else
			throw new IllegalArgumentException("only encryption and decryption supported");
		this.random = random;
		this.opmode = opmode;
		pos = 0;
		dataBuffer = new byte[outputLen];
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		throw new NoSuchAlgorithmException("only one mode available");
	}

	@Override
	protected void engineSetPadding(String pad) throws NoSuchPaddingException {
		throw new NoSuchPaddingException("only one padding available");
	}

	@Override
	protected byte[] engineUpdate(byte[] in, int offset, int length) {
		if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
			throw new IllegalStateException("not initialized");
		System.arraycopy(in, offset, dataBuffer, pos, length);
		pos += length;
		return EMPTY;
	}

	@Override
	protected int engineUpdate(byte[] in, int offset, int length, byte[] out, int outOffset) {
		engineUpdate(in, offset, length);
		return 0;
	}

	/**
	 * Decrypts the ciphertext, employing RSA blinding if possible.
	 */
	private byte[] rsaDecrypt(BigInteger enc) {
		if (random == null)
			random = new SecureRandom();
		BigInteger n = decipherKey.getModulus();
		BigInteger r = null;
		BigInteger pubExp = null;
		if (blindingKey != null)
			pubExp = blindingKey.getPublicExponent();
		if (pubExp != null && (decipherKey instanceof RSAPrivateCrtKey))
			pubExp = ((RSAPrivateCrtKey) decipherKey).getPublicExponent();
		if (pubExp != null) {
			r = new BigInteger(n.bitLength() - 1, random);
			enc = r.modPow(pubExp, n).multiply(enc).mod(n);
		}
		BigInteger dec = enc.modPow(decipherKey.getPrivateExponent(), n);
		if (pubExp != null) {
			dec = dec.multiply(r.modInverse(n)).mod(n);
		}

		byte[] decb = dec.toByteArray();
		if (decb[0] != 0x00) {
			byte[] b = new byte[decb.length + 1];
			System.arraycopy(decb, 0, b, 1, decb.length);
			decb = b;
		}
		return decb;
	}
}
