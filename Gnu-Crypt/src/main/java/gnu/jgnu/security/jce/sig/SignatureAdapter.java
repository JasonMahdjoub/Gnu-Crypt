/* SignatureAdapter.java --
   Copyright 2001, 2002, 2006, 2010 Free Software Foundation, Inc.

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

package gnu.jgnu.security.jce.sig;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

import gnu.jgnu.security.sig.ISignature;
import gnu.jgnu.security.sig.ISignatureCodec;
import gnu.jgnu.security.sig.SignatureFactory;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.InvalidParameterException;
import gnu.vm.jgnu.security.PrivateKey;
import gnu.vm.jgnu.security.PublicKey;
import gnu.vm.jgnu.security.SecureRandom;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.SignatureSpi;

/**
 * The implementation of a generic {@link gnu.vm.jgnu.security.Signature}
 * adapter class to wrap GNU signature instances.
 * <p>
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>) for the
 * {@link gnu.vm.jgnu.security.Signature} class, which provides the
 * functionality of a digital signature algorithm. Digital signatures are used
 * for authentication and integrity assurance of digital data.
 * <p>
 * All the abstract methods in the {@link SignatureSpi} class are implemented by
 * this class and all its sub-classes.
 * <p>
 * All the implementations which subclass this object, and which are serviced by
 * the GNU provider implement the {@link Cloneable} interface.
 */
class SignatureAdapter extends SignatureSpi implements Cloneable
{

    /** Our underlying signature instance. */
    private ISignature adaptee;

    /** Our underlying signature encoder/decoder engine. */
    private ISignatureCodec codec;

    /**
     * Private constructor for cloning purposes.
     *
     * @param adaptee
     *            a clone of the underlying signature scheme instance.
     * @param codec
     *            the signature codec engine to use with this scheme.
     */
    private SignatureAdapter(ISignature adaptee, ISignatureCodec codec)
    {
	super();

	this.adaptee = adaptee;
	this.codec = codec;
    }

    /**
     * Trivial protected constructor.
     *
     * @param sigName
     *            the canonical name of the signature scheme.
     * @param codec
     *            the signature codec engine to use with this scheme.
     */
    protected SignatureAdapter(String sigName, ISignatureCodec codec)
    {
	this(SignatureFactory.getInstance(sigName), codec);
    }

    @Override
    public Object clone()
    {
	return new SignatureAdapter((ISignature) adaptee.clone(), codec);
    }

    // Deprecated
    @Override
    public Object engineGetParameter(String param) throws InvalidParameterException
    {
	throw new InvalidParameterException("deprecated");
    }

    @Override
    public void engineInitSign(PrivateKey privateKey) throws InvalidKeyException
    {
	HashMap<String, PrivateKey> attributes = new HashMap<>();
	attributes.put(ISignature.SIGNER_KEY, privateKey);
	try
	{
	    adaptee.setupSign(attributes);
	}
	catch (IllegalArgumentException x)
	{
	    throw new InvalidKeyException(x.getMessage(), x);
	}
    }

    @Override
    public void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException
    {
	HashMap<String, Object> attributes = new HashMap<>();
	attributes.put(ISignature.SIGNER_KEY, privateKey);
	attributes.put(ISignature.SOURCE_OF_RANDOMNESS, random);
	try
	{
	    adaptee.setupSign(attributes);
	}
	catch (IllegalArgumentException x)
	{
	    throw new InvalidKeyException(x.getMessage(), x);
	}
    }

    @Override
    public void engineInitVerify(PublicKey publicKey) throws InvalidKeyException
    {
	HashMap<String, PublicKey> attributes = new HashMap<>();
	attributes.put(ISignature.VERIFIER_KEY, publicKey);
	try
	{
	    adaptee.setupVerify(attributes);
	}
	catch (IllegalArgumentException x)
	{
	    throw new InvalidKeyException(x.getMessage(), x);
	}
    }

    public void engineSetParameter(AlgorithmParameterSpec params)
    {
    }

    // Deprecated. Replaced by engineSetParameter.
    @Override
    public void engineSetParameter(String param, Object value) throws InvalidParameterException
    {
	throw new InvalidParameterException("deprecated");
    }

    @Override
    public byte[] engineSign() throws SignatureException
    {
	Object signature = null;
	try
	{
	    signature = adaptee.sign();
	}
	catch (IllegalStateException x)
	{
	    throw new SignatureException(x.getMessage(), x);
	}
	byte[] result = codec.encodeSignature(signature);
	return result;
    }

    @Override
    public int engineSign(byte[] outbuf, int offset, int len) throws SignatureException
    {
	byte[] signature = this.engineSign();
	int result = signature.length;
	if (result > len)
	    throw new SignatureException("Not enough room to store signature");

	System.arraycopy(signature, 0, outbuf, offset, result);
	return result;
    }

    @Override
    public void engineUpdate(byte b) throws SignatureException
    {
	try
	{
	    adaptee.update(b);
	}
	catch (IllegalStateException x)
	{
	    throw new SignatureException(x.getMessage(), x);
	}
    }

    @Override
    public void engineUpdate(byte[] b, int off, int len) throws SignatureException
    {
	try
	{
	    adaptee.update(b, off, len);
	}
	catch (IllegalStateException x)
	{
	    throw new SignatureException(x.getMessage(), x);
	}
    }

    @Override
    public boolean engineVerify(byte[] sigBytes) throws SignatureException
    {
	Object signature = codec.decodeSignature(sigBytes);
	boolean result = false;
	try
	{
	    result = adaptee.verify(signature);
	}
	catch (IllegalStateException x)
	{
	    throw new SignatureException(x.getMessage(), x);
	}
	return result;
    }
}
