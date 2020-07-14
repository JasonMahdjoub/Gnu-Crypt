/* KeyWrappingAlgorithmAdapter.java -- Base Adapter for Key Wrapping algorithms
   Copyright (C) 2006, 2010  Free Software Foundation, Inc.

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

package com.distrimind.gnu.jgnux.crypto.jce.cipher;

import java.util.HashMap;
import java.util.Map;

import com.distrimind.gnu.jgnu.security.Registry;
import com.distrimind.gnu.jgnux.crypto.jce.spec.BlockCipherParameterSpec;
import com.distrimind.gnu.jgnux.crypto.kwa.IKeyWrappingAlgorithm;
import com.distrimind.gnu.jgnux.crypto.kwa.KeyUnwrappingException;
import com.distrimind.gnu.jgnux.crypto.kwa.KeyWrappingAlgorithmFactory;
import com.distrimind.gnu.vm.jgnu.security.AlgorithmParameters;
import com.distrimind.gnu.vm.jgnu.security.InvalidKeyException;
import com.distrimind.gnu.vm.jgnu.security.Key;
import com.distrimind.gnu.vm.jgnu.security.KeyFactory;
import com.distrimind.gnu.vm.jgnu.security.NoSuchAlgorithmException;
import com.distrimind.gnu.vm.jgnu.security.SecureRandom;
import com.distrimind.gnu.vm.jgnu.security.spec.AlgorithmParameterSpec;
import com.distrimind.gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import com.distrimind.gnu.vm.jgnu.security.spec.InvalidParameterSpecException;
import com.distrimind.gnu.vm.jgnu.security.spec.X509EncodedKeySpec;
import com.distrimind.gnu.vm.jgnux.crypto.Cipher;
import com.distrimind.gnu.vm.jgnux.crypto.CipherSpi;
import com.distrimind.gnu.vm.jgnux.crypto.spec.IvParameterSpec;
import com.distrimind.gnu.vm.jgnux.crypto.spec.SecretKeySpec;

/**
 * An abstract base class to facilitate implementations of JCE Adapters for
 * symmetric key block ciphers capable of providing key-wrapping functionality.
 */
abstract class KeyWrappingAlgorithmAdapter extends CipherSpi {
	/** JCE canonical name of a null-padder. */
	private static final String NO_PADDING = "nopadding";

	/** Concrete Key Wrapping Algorithm SPI. */
	protected IKeyWrappingAlgorithm kwAlgorithm;

	/**
	 * Size in bytes of the padding block to be provided by external padders.
	 */
	protected int kwaBlockSize;

	/** KEK size in bytes. */
	protected int kwaKeySize;

	/** Name of the supported mode. */
	protected String supportedMode;

	/** Operational mode in which this instance was initialised. */
	protected int opmode = -1;

	/** Initialisation Vector if/when user wants to override default one. */
	byte[] iv;

	/**
	 * Creates a new JCE Adapter for the designated Key Wrapping Algorithm name.
	 *
	 * @param name
	 *            the canonical name of the key-wrapping algorithm.
	 * @param blockSize
	 *            the block size in bytes of the underlying symmetric-key block
	 *            cipher algorithm.
	 * @param keySize
	 *            the allowed size in bytes of the KEK bytes to initialise the
	 *            underlying symmetric-key block cipher algorithm with.
	 * @param supportedMode
	 *            canonical name of the block mode the underlying cipher is
	 *            supporting.
	 */
	protected KeyWrappingAlgorithmAdapter(String name, int blockSize, int keySize, String supportedMode) {
		super();

		this.kwAlgorithm = KeyWrappingAlgorithmFactory.getInstance(name);
		this.kwaBlockSize = blockSize;
		this.kwaKeySize = keySize;
		this.supportedMode = supportedMode;
	}

	/**
	 * Returns the key bytes, iff it was in RAW format.
	 *
	 * @param key
	 *            the opaque JCE secret key to use as the KEK.
	 * @return the bytes of the encoded form of the designated kek, iff it was in
	 *         RAW format.
	 * @throws InvalidKeyException
	 *             if the designated key is not in the RAW format.
	 */
	private byte[] checkAndGetKekBytes(Key key) throws InvalidKeyException {
		if (!Registry.RAW_ENCODING_SHORT_NAME.equalsIgnoreCase(key.getFormat()))
			throw new InvalidKeyException("Only RAW key format is supported");
		byte[] result = key.getEncoded();
		int kekSize = result.length;
		if (kekSize != kwaKeySize)
			throw new InvalidKeyException(
					"Invalid key material size. Expected " + kwaKeySize + " but found " + kekSize);
		return result;
	}

	private void checkOpMode(int opmode) {
		switch (opmode) {
		case Cipher.WRAP_MODE:
		case Cipher.UNWRAP_MODE:
			return;
		}
		throw new IllegalArgumentException("Unsupported operational mode: " + opmode);
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLength) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected int engineGetBlockSize() {
		return kwaBlockSize;
	}

	@Override
	protected byte[] engineGetIV() {
		return iv == null ? null : (byte[]) iv.clone();
	}

	@Override
	protected int engineGetOutputSize(int inputLength) {
		switch (opmode) {
		case Cipher.WRAP_MODE:
			return getOutputSizeForWrap(inputLength);
		case Cipher.UNWRAP_MODE:
			return getOutputSizeForUnwrap(inputLength);
		default:
			throw new IllegalStateException();
		}
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		BlockCipherParameterSpec spec = new BlockCipherParameterSpec(iv, kwaBlockSize, kwaKeySize);
		AlgorithmParameters result = null;
		try {
			result = AlgorithmParameters.getInstance("BlockCipherParameters");
			result.init(spec);
		} catch (NoSuchAlgorithmException x) {
		} catch (InvalidParameterSpecException x) {
		}
		return result;
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException {
		AlgorithmParameterSpec spec = null;
		try {
			if (params != null)
				spec = params.getParameterSpec(BlockCipherParameterSpec.class);
		} catch (InvalidParameterSpecException x) {
		}
		engineInit(opmode, key, spec, random);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException {
		checkOpMode(opmode);
		byte[] kekBytes = checkAndGetKekBytes(key);
		byte[] ivBytes = null;
		if (params instanceof BlockCipherParameterSpec)
			ivBytes = ((BlockCipherParameterSpec) params).getIV();
		else if (params instanceof IvParameterSpec)
			ivBytes = ((IvParameterSpec) params).getIV();

		initAlgorithm(opmode, kekBytes, ivBytes, random);
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		checkOpMode(opmode);
		byte[] kekBytes = checkAndGetKekBytes(key);
		initAlgorithm(opmode, kekBytes, null, random);
	}

	@Override
	protected void engineSetMode(String mode) {
		if (!supportedMode.equalsIgnoreCase(mode))
			throw new UnsupportedOperationException("Only " + supportedMode + " is supported");
	}

	/**
	 * NoPadding is the only padding algorithm supported by Key Wrapping Algorithm
	 * implementations in RI.
	 */
	@Override
	protected void engineSetPadding(String padding) {
		if (!NO_PADDING.equalsIgnoreCase(padding))
			throw new UnsupportedOperationException("Only NoPadding is supported");
	}

	/**
	 * Unwraps a previously-wrapped key-material.
	 *
	 * @param wrappedKey
	 *            the wrapped key-material to unwrap.
	 * @param wrappedKeyAlgorithm
	 *            the canonical name of the algorithm, which the unwrapped
	 *            key-material represents. This name is used to instantiate a
	 *            concrete instance of a {@link Key} for that algorithm. For
	 *            example, if the value of this parameter is <code>DSS</code> and
	 *            the type (the next parameter) is {@link Cipher#PUBLIC_KEY} then an
	 *            attempt to construct a concrete instance of a
	 *            {@link java.security.interfaces.DSAPublicKey}, using the unwrapped
	 *            key material, shall be made.
	 * @param wrappedKeyType
	 *            the type of wrapped key-material. MUST be one of
	 *            {@link Cipher#PRIVATE_KEY}, {@link Cipher#PUBLIC_KEY}, or
	 *            {@link Cipher#SECRET_KEY}.
	 * @return the unwrapped key-material as an instance of {@link Key} or one of
	 *         its subclasses.
	 * @throws InvalidKeyException
	 *             If the key cannot be unwrapped, or if <code>wrappedKeyType</code>
	 *             is an inappropriate type for the unwrapped key.
	 * @throws NoSuchAlgorithmException
	 *             If the <code>wrappedKeyAlgorithm</code> is unknown to every
	 *             currently installed Security Provider.
	 */
	@Override
	protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
			throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] keyBytes;
		try {
			keyBytes = kwAlgorithm.unwrap(wrappedKey, 0, wrappedKey.length);
		} catch (KeyUnwrappingException x) {
			InvalidKeyException y = new InvalidKeyException("engineUnwrap()");
			y.initCause(x);
			throw y;
		}
		Key result;
		switch (wrappedKeyType) {
		case Cipher.SECRET_KEY:
			result = new SecretKeySpec(keyBytes, wrappedKeyAlgorithm);
			break;
		case Cipher.PRIVATE_KEY:
		case Cipher.PUBLIC_KEY:
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(wrappedKeyAlgorithm);
			try {
				if (wrappedKeyType == Cipher.PRIVATE_KEY)
					result = keyFactory.generatePrivate(keySpec);
				else
					result = keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException x) {
				InvalidKeyException y = new InvalidKeyException("engineUnwrap()");
				y.initCause(x);
				throw y;
			}
			break;
		default:
			IllegalArgumentException x = new IllegalArgumentException("Invalid 'wrappedKeyType': " + wrappedKeyType);
			InvalidKeyException y = new InvalidKeyException("engineUnwrap()");
			y.initCause(x);
			throw y;
		}
		return result;
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLength) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Wraps the encoded form of a designated {@link Key}.
	 *
	 * @param key
	 *            the key-material to wrap.
	 * @return the wrapped key.
	 * @throws InvalidKeyException
	 *             If the key cannot be wrapped.
	 */
	@Override
	protected byte[] engineWrap(Key key) throws InvalidKeyException {
		byte[] keyMaterial = key.getEncoded();
		byte[] result = kwAlgorithm.wrap(keyMaterial, 0, keyMaterial.length);
		return result;
	}

	/**
	 * Return the minimum size in bytes of a place holder large enough to receive
	 * the plain text resulting from an unwrap method with the designated size of
	 * the cipher text.
	 * <p>
	 * This default implementation ALWAYS returns the smallest multiple of the
	 * <code>paddingBlockSize</code> --passed to this method through its
	 * constructor-- greater than or equal to the designated
	 * <code>inputLength</code>.
	 *
	 * @param inputLength
	 *            the size of a cipher text.
	 * @return an estimate of the size, in bytes, of the place holder to receive the
	 *         resulting bytes of an uwrap method.
	 */
	protected int getOutputSizeForUnwrap(int inputLength) {
		return kwaBlockSize * (inputLength + kwaBlockSize - 1) / kwaBlockSize;
	}

	/**
	 * Return the minimum size in bytes of a place holder large enough to receive
	 * the cipher text resulting from a wrap method with the designated size of the
	 * plain text.
	 * <p>
	 * This default implementation ALWAYS returns the smallest multiple of the
	 * <code>kwaBlockSize</code> --passed to this method through its constructor--
	 * greater than or equal to the designated <code>inputLength</code>.
	 *
	 * @param inputLength
	 *            the size of a plain text.
	 * @return an estimate of the size, in bytes, of the place holder to receive the
	 *         resulting bytes of a wrap method.
	 */
	protected int getOutputSizeForWrap(int inputLength) {
		return kwaBlockSize * (inputLength + kwaBlockSize - 1) / kwaBlockSize;
	}

	private void initAlgorithm(int opmode, byte[] kek, byte[] ivBytes, SecureRandom rnd) throws InvalidKeyException {
		this.opmode = opmode;
		Map<Object, Object> attributes = new HashMap<>();
		attributes.put(IKeyWrappingAlgorithm.KEY_ENCRYPTION_KEY_MATERIAL, kek);
		if (ivBytes != null) {
			this.iv = ivBytes.clone();
			attributes.put(IKeyWrappingAlgorithm.INITIAL_VALUE, this.iv);
		} else
			this.iv = null;
		if (rnd != null)
			attributes.put(IKeyWrappingAlgorithm.SOURCE_OF_RANDOMNESS, rnd);

		kwAlgorithm.init(attributes);
	}
}
