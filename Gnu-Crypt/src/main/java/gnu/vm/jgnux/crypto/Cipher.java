/* Cipher.java -- Interface to a cryptographic cipher.
   Copyright (C) 2004, 2006  Free Software Foundation, Inc.

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

package gnu.vm.jgnux.crypto;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.StringTokenizer;

import gnu.jgnu.security.Engine;
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.Cipher;
import gnu.vm.jgnux.crypto.CipherSpi;
import gnu.vm.jgnux.crypto.ExemptionMechanism;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.ShortBufferException;
import gnu.vm.jgnu.security.AlgorithmParameters;
import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.Key;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.Provider;
import gnu.vm.jgnu.security.SecureRandom;
import gnu.vm.jgnu.security.Security;
import gnu.vm.jgnu.security.cert.Certificate;
import gnu.vm.jgnu.security.cert.X509Certificate;
import gnu.vm.jgnu.security.spec.AlgorithmParameterSpec;

/**
 * <p>
 * This class implements a cryptographic cipher for transforming data.
 * </p>
 *
 * <p>
 * Ciphers cannot be instantiated directly; rather one of the
 * <code>getInstance</code> must be used to instantiate a given
 * <i>transformation</i>, optionally with a specific provider.
 * </p>
 *
 * <p>
 * A transformation is of the form:
 * </p>
 *
 * <ul>
 * <li><i>algorithm</i>/<i>mode</i>/<i>padding</i>, or</li>
 * <li><i>algorithm</i>
 * </ul>
 *
 * <p>
 * where <i>algorithm</i> is the base name of a cryptographic cipher (such as
 * "AES"), <i>mode</i> is the abbreviated name of a block cipher mode (such as
 * "CBC" for cipher block chaining mode), and <i>padding</i> is the name of a
 * padding scheme (such as "PKCS5Padding"). If only the algorithm name is
 * supplied, then the provider-specific default mode and padding will be used.
 * </p>
 *
 * <p>
 * An example transformation is:
 * </p>
 *
 * <blockquote><code>Cipher c =
 * Cipher.getInstance("AES/CBC/PKCS5Padding");</code></blockquote>
 *
 * <p>
 * Finally, when requesting a block cipher in stream cipher mode (such as
 * <acronym title="Advanced Encryption Standard">AES</acronym> in OFB or CFB
 * mode) the number of bits to be processed at a time may be specified by
 * appending it to the name of the mode; e.g. <code>"AES/OFB8/NoPadding"</code>.
 * If no such number is specified a provider-specific default value is used.
 * </p>
 *
 * @author Casey Marshall (csm@gnu.org)
 * @see java.security.KeyGenerator
 * @see gnu.vm.jgnux.crypto.SecretKey
 */
public class Cipher
{

    // Constants and variables.
    // ------------------------------------------------------------------------

    private static final String SERVICE = "Cipher";

    /**
     * The decryption operation mode.
     */
    public static final int DECRYPT_MODE = 2;

    /**
     * The encryption operation mode.
     */
    public static final int ENCRYPT_MODE = 1;

    /**
     * Constant for when the key to be unwrapped is a private key.
     */
    public static final int PRIVATE_KEY = 2;

    /**
     * Constant for when the key to be unwrapped is a public key.
     */
    public static final int PUBLIC_KEY = 1;

    /**
     * Constant for when the key to be unwrapped is a secret key.
     */
    public static final int SECRET_KEY = 3;

    /**
     * The key unwrapping operation mode.
     */
    public static final int UNWRAP_MODE = 4;

    /**
     * The key wrapping operation mode.
     */
    public static final int WRAP_MODE = 3;

    /**
     * The uninitialized state. This state signals that any of the
     * <code>init</code> methods have not been called, and therefore no
     * transformations can be done.
     */
    private static final int INITIAL_STATE = 0;

    /**
     * Creates a new cipher instance for the given transformation.
     * <p>
     * The installed providers are tried in order for an implementation, and the
     * first appropriate instance is returned. If no installed provider can
     * provide the implementation, an appropriate exception is thrown.
     *
     * @param transformation
     *            The transformation to create.
     * @return An appropriate cipher for this transformation.
     * @throws NoSuchAlgorithmException
     *             If no installed provider can supply the appropriate cipher or
     *             mode.
     * @throws NoSuchPaddingException
     *             If no installed provider can supply the appropriate padding.
     */
    public static final Cipher getInstance(String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	Provider[] p = Security.getProviders();
	NoSuchAlgorithmException lastException = null;
	NoSuchPaddingException lastPaddingException = null;
	for (int i = 0; i < p.length; i++)
	{
	    try
	    {
		return getInstance(transformation, p[i]);
	    }
	    catch (NoSuchAlgorithmException x)
	    {
		lastException = x;
		lastPaddingException = null;
	    }
	    catch (NoSuchPaddingException x)
	    {
		lastPaddingException = x;
	    }
	}
	if (lastPaddingException != null)
	    throw lastPaddingException;
	if (lastException != null)
	    throw lastException;
	throw new NoSuchAlgorithmException(transformation);
    }

    /**
     * Creates a new cipher instance for a given transformation from a given
     * provider.
     *
     * @param transformation
     *            The transformation to create.
     * @param provider
     *            The provider to use.
     * @return An appropriate cipher for this transformation.
     * @throws NoSuchAlgorithmException
     *             If the given provider cannot supply the appropriate cipher or
     *             mode.
     * @throws NoSuchPaddingException
     *             If the given provider cannot supply the appropriate padding
     *             scheme.
     */
    public static final Cipher getInstance(String transformation, Provider provider) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	StringBuilder sb = new StringBuilder().append("Cipher transformation [")
		.append(transformation).append("] from provider [")
		.append(provider).append("] ");
	Throwable cause;
	Object spi;
	CipherSpi result;
	if (transformation.indexOf('/') < 0)
	{
	    try
	    {
		spi = Engine.getInstance(SERVICE, transformation, provider);
		return new Cipher((CipherSpi) spi, provider, transformation);
	    }
	    catch (Exception e)
	    {
		if (e instanceof NoSuchAlgorithmException)
		    throw (NoSuchAlgorithmException) e;
		cause = e;
	    }
	}
	else
	{
	    StringTokenizer tok = new StringTokenizer(transformation, "/");
	    if (tok.countTokens() != 3)
		throw new NoSuchAlgorithmException(
			sb.append("is malformed").toString());

	    String alg = tok.nextToken();
	    String mode = tok.nextToken();
	    String pad = tok.nextToken();
	    try
	    {
		spi = Engine.getInstance(SERVICE, transformation, provider);
		return new Cipher((CipherSpi) spi, provider, transformation);
	    }
	    catch (Exception e)
	    {
		cause = e;
	    }

	    try
	    {
		spi = Engine.getInstance(SERVICE, alg + '/' + mode, provider);
		result = (CipherSpi) spi;
		result.engineSetPadding(pad);
		return new Cipher(result, provider, transformation);
	    }
	    catch (Exception e)
	    {
		if (e instanceof NoSuchPaddingException)
		    throw (NoSuchPaddingException) e;
		cause = e;
	    }

	    try
	    {
		spi = Engine.getInstance(SERVICE, alg + "//" + pad, provider);
		result = (CipherSpi) spi;
		result.engineSetMode(mode);
		return new Cipher(result, provider, transformation);
	    }
	    catch (Exception e)
	    {
		cause = e;
	    }

	    try
	    {
		spi = Engine.getInstance(SERVICE, alg, provider);
		result = (CipherSpi) spi;
		result.engineSetMode(mode);
		result.engineSetPadding(pad);
		return new Cipher(result, provider, transformation);
	    }
	    catch (Exception e)
	    {
		if (e instanceof NoSuchPaddingException)
		    throw (NoSuchPaddingException) e;
		cause = e;
	    }
	}
	sb.append("could not be created");
	NoSuchAlgorithmException x = new NoSuchAlgorithmException(
		sb.toString());
	x.initCause(cause);
	throw x;
    }

    /**
     * Creates a new cipher instance for the given transformation and the named
     * provider.
     *
     * @param transformation
     *            The transformation to create.
     * @param provider
     *            The name of the provider to use.
     * @return An appropriate cipher for this transformation.
     * @throws NoSuchAlgorithmException
     *             If the provider cannot supply the appropriate cipher or mode.
     * @throws NoSuchProviderException
     *             If the named provider is not installed.
     * @throws NoSuchPaddingException
     *             If the provider cannot supply the appropriate padding.
     * @throws IllegalArgumentException
     *             if either <code>transformation</code> or
     *             <code>provider</code> is <code>null</code>.
     */
    public static final Cipher getInstance(String transformation, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
    {
	if (provider == null)
	    throw new IllegalArgumentException("provider MUST NOT be null");
	Provider p = Security.getProvider(provider);
	if (p == null)
	    throw new NoSuchProviderException(provider);
	return getInstance(transformation, p);
    }

    /** The underlying cipher service provider interface. */
    private CipherSpi cipherSpi;

    /** The provider from which this instance came. */
    private Provider provider;

    /** The transformation requested. */
    private String transformation;

    /** Our current state (encrypting, wrapping, etc.) */
    private int state;

    /**
     * Create a cipher.
     *
     * @param cipherSpi
     *            The underlying implementation of the cipher.
     * @param provider
     *            The provider of this cipher implementation.
     * @param transformation
     *            The transformation this cipher performs.
     */
    protected Cipher(CipherSpi cipherSpi, Provider provider, String transformation)
    {
	this.cipherSpi = cipherSpi;
	this.provider = provider;
	this.transformation = transformation;
	state = INITIAL_STATE;
    }

    /**
     * Finishes a multi-part transformation, and returns the final transformed
     * bytes.
     *
     * @return The final transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the input is not a
     *             multiple of this cipher's block size.
     * @throws gnu.vm.jgnux.crypto.BadPaddingException
     *             If this instance is decrypting and the padding bytes do not
     *             match this instance's padding scheme.
     */
    public final byte[] doFinal() throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	return doFinal(new byte[0], 0, 0);
    }

    /**
     * Finishes a multi-part transformation or does an entire transformation on
     * the input, and returns the transformed bytes.
     *
     * @param input
     *            The final input bytes.
     * @return The final transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the input is not a
     *             multiple of this cipher's block size.
     * @throws gnu.vm.jgnux.crypto.BadPaddingException
     *             If this instance is decrypting and the padding bytes do not
     *             match this instance's padding scheme.
     */
    public final byte[] doFinal(byte[] input) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	return doFinal(input, 0, input.length);
    }

    /**
     * Finishes a multi-part transformation and stores the transformed bytes
     * into the given array.
     *
     * @param output
     *            The destination for the transformed bytes.
     * @param outputOffset
     *            The offset in <tt>output</tt> to start storing bytes.
     * @return The number of bytes placed into the output array.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the input is not a
     *             multiple of this cipher's block size.
     * @throws gnu.vm.jgnux.crypto.BadPaddingException
     *             If this instance is decrypting and the padding bytes do not
     *             match this instance's padding scheme.
     * @throws gnu.vm.jgnux.crypto.ShortBufferException
     *             If the output array is not large enough to hold the
     *             transformed bytes.
     */
    public final int doFinal(byte[] output, int outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	if (cipherSpi == null)
	{
	    return 0;
	}
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	{
	    throw new IllegalStateException(
		    "neither encrypting nor decrypting");
	}
	return cipherSpi.engineDoFinal(new byte[0], 0, 0, output, outputOffset);
    }

    /**
     * Finishes a multi-part transformation or does an entire transformation on
     * the input, and returns the transformed bytes.
     *
     * @param input
     *            The final input bytes.
     * @param inputOffset
     *            The index in the input bytes to start.
     * @param inputLength
     *            The number of bytes to read from the input.
     * @return The final transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the input is not a
     *             multiple of this cipher's block size.
     * @throws gnu.vm.jgnux.crypto.BadPaddingException
     *             If this instance is decrypting and the padding bytes do not
     *             match this instance's padding scheme.
     */
    public final byte[] doFinal(byte[] input, int inputOffset, int inputLength) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	if (cipherSpi == null)
	{
	    byte[] b = new byte[inputLength];
	    System.arraycopy(input, inputOffset, b, 0, inputLength);
	    return b;
	}
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	{
	    throw new IllegalStateException(
		    "neither encrypting nor decrypting");
	}
	return cipherSpi.engineDoFinal(input, inputOffset, inputLength);
    }

    public final int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	return doFinal(input, inputOffset, inputLength, output, 0);
    }

    /**
     * Finishes a multi-part transformation or transforms a portion of a byte
     * array, and stores the result in the given byte array.
     *
     * @param input
     *            The input bytes.
     * @param inputOffset
     *            The index in <tt>input</tt> to start.
     * @param inputLength
     *            The number of bytes to transform.
     * @param output
     *            The output buffer.
     * @param outputOffset
     *            The index in <tt>output</tt> to start.
     * @return The number of bytes placed into the output array.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the input is not a
     *             multiple of this cipher's block size.
     * @throws gnu.vm.jgnux.crypto.BadPaddingException
     *             If this instance is decrypting and the padding bytes do not
     *             match this instance's padding scheme.
     * @throws gnu.vm.jgnux.crypto.ShortBufferException
     *             If the output array is not large enough to hold the
     *             transformed bytes.
     */
    public final int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	if (cipherSpi == null)
	{
	    if (inputLength > output.length - outputOffset)
	    {
		throw new ShortBufferException();
	    }
	    System.arraycopy(input, inputOffset, output, outputOffset,
		    inputLength);
	    return inputLength;
	}
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	{
	    throw new IllegalStateException(
		    "neither encrypting nor decrypting");
	}
	return cipherSpi.engineDoFinal(input, inputOffset, inputLength, output,
		outputOffset);
    }

    /**
     * Finishes a multi-part transformation with, or completely transforms, a
     * byte buffer, and stores the result into the output buffer.
     *
     * @param input
     *            The input buffer.
     * @param output
     *            The output buffer.
     * @return The number of bytes stored into the output buffer.
     * @throws IllegalArgumentException
     *             If the input and output buffers are the same object.
     * @throws IllegalStateException
     *             If this cipher was not initialized for encryption or
     *             decryption.
     * @throws ReadOnlyBufferException
     *             If the output buffer is not writable.
     * @throws IllegalBlockSizeException
     *             If this cipher requires a total input that is a multiple of
     *             its block size to complete this transformation.
     * @throws ShortBufferException
     *             If the output buffer is not large enough to hold the
     *             transformed bytes.
     * @throws BadPaddingException
     *             If the cipher is a block cipher with a padding scheme, and
     *             the decrypted bytes do not end with a valid padding.
     * @since 1.5
     */
    public final int doFinal(ByteBuffer input, ByteBuffer output) throws ReadOnlyBufferException, ShortBufferException, BadPaddingException, IllegalBlockSizeException
    {
	if (input == output)
	    throw new IllegalArgumentException(
		    "input and output buffers cannot be the same");
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	    throw new IllegalStateException(
		    "not initialized for encrypting or decrypting");
	return cipherSpi.engineDoFinal(input, output);
    }

    /**
     * Get the name that this cipher instance was created with; this is
     * equivalent to the "transformation" argument given to any of the
     * {@link #getInstance()} methods.
     *
     * @return The cipher name.
     */
    public final String getAlgorithm()
    {
	return transformation;
    }

    /**
     * Return the size of blocks, in bytes, that this cipher processes.
     *
     * @return The block size.
     */
    public final int getBlockSize()
    {
	if (cipherSpi != null)
	{
	    return cipherSpi.engineGetBlockSize();
	}
	return 1;
    }

    /**
     * Return the currently-operating {@link ExemptionMechanism}.
     *
     * @return null, currently.
     */
    public final ExemptionMechanism getExemptionMechanism()
    {
	return null;
    }

    /**
     * Return the <i>initialization vector</i> that this instance was
     * initialized with.
     *
     * @return The IV.
     */
    public final byte[] getIV()
    {
	if (cipherSpi != null)
	{
	    return cipherSpi.engineGetIV();
	}
	return null;
    }

    /**
     * Returns the size an output buffer needs to be if this cipher is updated
     * with a number of bytes.
     *
     * @param inputLength
     *            The input length.
     * @return The output length given this input length.
     * @throws java.lang.IllegalStateException
     *             If this instance has not been initialized, or if a
     *             <tt>doFinal</tt> call has already been made.
     */
    public final int getOutputSize(int inputLength) throws IllegalStateException
    {
	if (cipherSpi == null)
	    return inputLength;
	return cipherSpi.engineGetOutputSize(inputLength);
    }

    /**
     * Return the {@link java.security.AlgorithmParameters} that this instance
     * was initialized with.
     *
     * @return The parameters.
     */
    public final AlgorithmParameters getParameters()
    {
	if (cipherSpi != null)
	{
	    return cipherSpi.engineGetParameters();
	}
	return null;
    }

    /**
     * Return this cipher's provider.
     *
     * @return The provider.
     */
    public final Provider getProvider()
    {
	return provider;
    }

    /**
     * <p>
     * Initialize this cipher with the public key from the given certificate.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * As per the Java 1.4 specification, if <code>cert</code> is an instance of
     * an {@link java.security.cert.X509Certificate} and its <i>key usage</i>
     * extension field is incompatible with <code>opmode</code> then an
     * {@link java.security.InvalidKeyException} is thrown.
     * </p>
     *
     * <p>
     * If this cipher requires any random bytes (for example for an
     * initilization vector) than the {@link java.security.SecureRandom} with
     * the highest priority is used as the source of these bytes.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param certificate
     *            The certificate.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the certificate's
     *             public key, or if the public key cannot be used as described
     *             above.
     */
    public final void init(int opmode, Certificate certificate) throws InvalidKeyException
    {
	init(opmode, certificate, new SecureRandom());
    }

    /**
     * <p>
     * Initialize this cipher with the public key from the given certificate and
     * the specified source of randomness.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * As per the Java 1.4 specification, if <code>cert</code> is an instance of
     * an {@link java.security.cert.X509Certificate} and its <i>key usage</i>
     * extension field is incompatible with <code>opmode</code> then an
     * {@link java.security.InvalidKeyException} is thrown.
     * </p>
     *
     * <p>
     * If this cipher requires any random bytes (for example for an
     * initilization vector) than the {@link java.security.SecureRandom} with
     * the highest priority is used as the source of these bytes.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param certificate
     *            The certificate.
     * @param random
     *            The source of randomness.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the certificate's
     *             public key, or if the public key cannot be used as described
     *             above.
     */
    public final void init(int opmode, Certificate certificate, SecureRandom random) throws InvalidKeyException
    {
	if (certificate instanceof X509Certificate)
	{
	    boolean[] keyInfo = ((X509Certificate) certificate).getKeyUsage();
	    if (keyInfo != null)
	    {
		switch (opmode)
		{
		    case DECRYPT_MODE:
			if (!keyInfo[3])
			{
			    throw new InvalidKeyException(
				    "the certificate's key cannot be used for transforming data");
			}
			if (keyInfo[7])
			{
			    throw new InvalidKeyException(
				    "the certificate's key can only be used for encryption");
			}
			break;

		    case ENCRYPT_MODE:
			if (!keyInfo[3])
			{
			    throw new InvalidKeyException(
				    "the certificate's key cannot be used for transforming data");
			}
			if (keyInfo[8])
			{
			    throw new InvalidKeyException(
				    "the certificate's key can only be used for decryption");
			}
			break;

		    case UNWRAP_MODE:
			if (!keyInfo[2] || keyInfo[7])
			{
			    throw new InvalidKeyException(
				    "the certificate's key cannot be used for key unwrapping");
			}
			break;

		    case WRAP_MODE:
			if (!keyInfo[2] || keyInfo[8])
			{
			    throw new InvalidKeyException(
				    "the certificate's key cannot be used for key wrapping");
			}
			break;
		}
	    }
	}
	init(opmode, certificate.getPublicKey(), random);
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * If this cipher requires any random bytes (for example for an
     * initilization vector) than the {@link java.security.SecureRandom} with
     * the highest priority is used as the source of these bytes.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     */
    public final void init(int opmode, Key key) throws InvalidKeyException
    {
	if (cipherSpi != null)
	{
	    cipherSpi.engineInit(opmode, key, new SecureRandom());
	}
	state = opmode;
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key and parameters.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * If this cipher requires any random bytes (for example for an
     * initilization vector) then the {@link java.security.SecureRandom} with
     * the highest priority is used as the source of these bytes.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @param params
     *            The algorithm parameters to initialize this instance with.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     * @throws java.security.InvalidAlgorithmParameterException
     *             If the supplied parameters are inappropriate for this cipher.
     */
    public final void init(int opmode, Key key, AlgorithmParameters params) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	init(opmode, key, params, new SecureRandom());
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key, parameters, and source of
     * randomness.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @param params
     *            The algorithm parameters to initialize this instance with.
     * @param random
     *            The source of randomness to use.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     * @throws java.security.InvalidAlgorithmParameterException
     *             If the supplied parameters are inappropriate for this cipher.
     */
    public final void init(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	if (cipherSpi != null)
	{
	    cipherSpi.engineInit(opmode, key, params, random);
	}
	state = opmode;
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key and parameters.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * If this cipher requires any random bytes (for example for an
     * initilization vector) then the {@link java.security.SecureRandom} with
     * the highest priority is used as the source of these bytes.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @param params
     *            The algorithm parameters to initialize this instance with.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     * @throws java.security.InvalidAlgorithmParameterException
     *             If the supplied parameters are inappropriate for this cipher.
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	init(opmode, key, params, new SecureRandom());
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key, parameters, and source of
     * randomness.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @param params
     *            The algorithm parameters to initialize this instance with.
     * @param random
     *            The source of randomness to use.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     * @throws java.security.InvalidAlgorithmParameterException
     *             If the supplied parameters are inappropriate for this cipher.
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	if (cipherSpi != null)
	{
	    cipherSpi.engineInit(opmode, key, params, random);
	}
	state = opmode;
    }

    /**
     * <p>
     * Initialize this cipher with the supplied key and source of randomness.
     * </p>
     *
     * <p>
     * The cipher will be initialized for encryption, decryption, key wrapping,
     * or key unwrapping, depending upon whether the <code>opmode</code>
     * argument is {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE},
     * {@link #WRAP_MODE}, or {@link #UNWRAP_MODE}, respectively.
     * </p>
     *
     * <p>
     * A call to any of the <code>init</code> methods overrides the state of the
     * instance, and is equivalent to creating a new instance and calling its
     * <code>init</code> method.
     * </p>
     *
     * @param opmode
     *            The operation mode to use.
     * @param key
     *            The key.
     * @param random
     *            The source of randomness to use.
     * @throws java.security.InvalidKeyException
     *             If the underlying cipher instance rejects the given key.
     */
    public final void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
	if (cipherSpi != null)
	{
	    cipherSpi.engineInit(opmode, key, random);
	}
	state = opmode;
    }

    /**
     * Unwrap a previously-wrapped key.
     *
     * @param wrappedKey
     *            The wrapped key.
     * @param wrappedKeyAlgorithm
     *            The algorithm with which the key was wrapped.
     * @param wrappedKeyType
     *            The type of key (public, private, or secret) that this wrapped
     *            key respresents.
     * @return The unwrapped key.
     * @throws java.lang.IllegalStateException
     *             If this instance has not be initialized for unwrapping.
     * @throws java.security.InvalidKeyException
     *             If <code>wrappedKey</code> is not a wrapped key, if the
     *             algorithm cannot unwrap this key, or if the unwrapped key's
     *             type differs from the specified type.
     * @throws java.security.NoSuchAlgorithmException
     *             If <code>wrappedKeyAlgorithm</code> is not a valid algorithm
     *             name.
     */
    public final Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws IllegalStateException, InvalidKeyException, NoSuchAlgorithmException
    {
	if (cipherSpi == null)
	{
	    return null;
	}
	if (state != UNWRAP_MODE)
	{
	    throw new IllegalStateException("instance is not for unwrapping");
	}
	return cipherSpi.engineUnwrap(wrappedKey, wrappedKeyAlgorithm,
		wrappedKeyType);
    }

    /**
     * Continue a multi-part transformation on an entire byte array, returning
     * the transformed bytes.
     *
     * @param input
     *            The input bytes.
     * @return The transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this cipher was not initialized for encryption or
     *             decryption.
     */
    public final byte[] update(byte[] input) throws IllegalStateException
    {
	return update(input, 0, input.length);
    }

    /**
     * Continue a multi-part transformation on part of a byte array, returning
     * the transformed bytes.
     *
     * @param input
     *            The input bytes.
     * @param inputOffset
     *            The index in the input to start.
     * @param inputLength
     *            The number of bytes to transform.
     * @return The transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this cipher was not initialized for encryption or
     *             decryption.
     */
    public final byte[] update(byte[] input, int inputOffset, int inputLength) throws IllegalStateException
    {
	if (cipherSpi == null)
	{
	    byte[] b = new byte[inputLength];
	    System.arraycopy(input, inputOffset, b, 0, inputLength);
	    return b;
	}
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	{
	    throw new IllegalStateException(
		    "cipher is not for encrypting or decrypting");
	}
	return cipherSpi.engineUpdate(input, inputOffset, inputLength);
    }

    /**
     * Continue a multi-part transformation on part of a byte array, placing the
     * transformed bytes into the given array.
     *
     * @param input
     *            The input bytes.
     * @param inputOffset
     *            The index in the input to start.
     * @param inputLength
     *            The number of bytes to transform.
     * @param output
     *            The output byte array.
     * @return The number of transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this cipher was not initialized for encryption or
     *             decryption.
     * @throws javax.security.ShortBufferException
     *             If there is not enough room in the output array to hold the
     *             transformed bytes.
     */
    public final int update(byte[] input, int inputOffset, int inputLength, byte[] output) throws IllegalStateException, ShortBufferException
    {
	return update(input, inputOffset, inputLength, output, 0);
    }

    /**
     * Continue a multi-part transformation on part of a byte array, placing the
     * transformed bytes into the given array.
     *
     * @param input
     *            The input bytes.
     * @param inputOffset
     *            The index in the input to start.
     * @param inputLength
     *            The number of bytes to transform.
     * @param output
     *            The output byte array.
     * @param outputOffset
     *            The index in the output array to start.
     * @return The number of transformed bytes.
     * @throws java.lang.IllegalStateException
     *             If this cipher was not initialized for encryption or
     *             decryption.
     * @throws javax.security.ShortBufferException
     *             If there is not enough room in the output array to hold the
     *             transformed bytes.
     */
    public final int update(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IllegalStateException, ShortBufferException
    {
	if (cipherSpi == null)
	{
	    if (inputLength > output.length - outputOffset)
	    {
		throw new ShortBufferException();
	    }
	    System.arraycopy(input, inputOffset, output, outputOffset,
		    inputLength);
	    return inputLength;
	}
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	{
	    throw new IllegalStateException(
		    "cipher is not for encrypting or decrypting");
	}
	return cipherSpi.engineUpdate(input, inputOffset, inputLength, output,
		outputOffset);
    }

    /**
     * Continue a multi-part transformation on a byte buffer, storing the
     * transformed bytes into another buffer.
     *
     * @param input
     *            The input buffer.
     * @param output
     *            The output buffer.
     * @return The number of bytes stored in <i>output</i>.
     * @throws IllegalArgumentException
     *             If the two buffers are the same object.
     * @throws IllegalStateException
     *             If this cipher was not initialized for encrypting or
     *             decrypting.
     * @throws ReadOnlyBufferException
     *             If the output buffer is not writable.
     * @throws ShortBufferException
     *             If the output buffer does not have enough available space for
     *             the transformed bytes.
     * @since 1.5
     */
    public final int update(ByteBuffer input, ByteBuffer output) throws ReadOnlyBufferException, ShortBufferException
    {
	if (input == output)
	    throw new IllegalArgumentException(
		    "input and output buffers must be different");
	if (state != ENCRYPT_MODE && state != DECRYPT_MODE)
	    throw new IllegalStateException(
		    "not initialized for encryption or decryption");
	return cipherSpi.engineUpdate(input, output);
    }

    /**
     * Wrap a key.
     *
     * @param key
     *            The key to wrap.
     * @return The wrapped key.
     * @throws java.lang.IllegalStateException
     *             If this instance was not initialized for key wrapping.
     * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
     *             If this instance has no padding and the key is not a multiple
     *             of the block size.
     * @throws java.security.InvalidKeyException
     *             If this instance cannot wrap this key.
     */
    public final byte[] wrap(Key key) throws IllegalStateException, IllegalBlockSizeException, InvalidKeyException
    {
	if (cipherSpi == null)
	{
	    return null;
	}
	if (state != WRAP_MODE)
	{
	    throw new IllegalStateException("instance is not for key wrapping");
	}
	return cipherSpi.engineWrap(key);
    }
}
