/* ARCFourSpi.java --
   Copyright (C) 2002, 2006  Free Software Foundation, Inc.

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

package gnu.jgnux.crypto.jce.cipher;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.ShortBufferException;

import gnu.jgnu.security.Registry;
import gnu.jgnu.security.prng.IRandom;
import gnu.jgnu.security.prng.LimitReachedException;
import gnu.jgnux.crypto.prng.ARCFour;
import gnu.jgnux.crypto.prng.PRNGFactory;

/**
 * The <i>Service Provider Interface</i> (<b>SPI</b>) for the ARCFOUR stream
 * cipher.
 */
public class ARCFourSpi extends CipherSpi
{
    private IRandom keystream;

    public ARCFourSpi()
    {
	super();
	keystream = PRNGFactory.getInstance(Registry.ARCFOUR_PRNG);
    }

    @Override
    protected byte[] engineDoFinal(byte[] in, int offset, int length)
    {
	return engineUpdate(in, offset, length);
    }

    @Override
    protected int engineDoFinal(byte[] in, int inOffset, int length, byte[] out, int outOffset) throws ShortBufferException
    {
	return engineUpdate(in, inOffset, length, out, outOffset);
    }

    @Override
    protected int engineGetBlockSize()
    {
	return 0; // stream cipher.
    }

    @Override
    protected byte[] engineGetIV()
    {
	return null;
    }

    @Override
    protected int engineGetOutputSize(int in)
    {
	return in;
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
	return null;
    }

    @Override
    protected void engineInit(int mode, Key key, AlgorithmParameters p, SecureRandom r) throws InvalidKeyException
    {
	engineInit(mode, key, r);
    }

    @Override
    protected void engineInit(int mode, Key key, AlgorithmParameterSpec p, SecureRandom r) throws InvalidKeyException
    {
	engineInit(mode, key, r);
    }

    @Override
    protected void engineInit(int mode, Key key, SecureRandom r) throws InvalidKeyException
    {
	if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE)
	    throw new IllegalArgumentException(
		    "arcfour is for encryption or decryption only");
	if (key == null || !key.getFormat().equalsIgnoreCase("RAW"))
	    throw new InvalidKeyException("key must be non-null raw bytes");
	HashMap<Object, Object> attrib = new HashMap<>();
	attrib.put(ARCFour.ARCFOUR_KEY_MATERIAL, key.getEncoded());
	keystream.init(attrib);
    }

    @Override
    protected void engineSetMode(String s)
    {
	// ignored.
    }

    @Override
    protected void engineSetPadding(String s)
    {
	// ignored.
    }

    @Override
    protected byte[] engineUpdate(byte[] in, int offset, int length)
    {
	if (length < 0 || offset < 0 || length + offset > in.length)
	    throw new ArrayIndexOutOfBoundsException();
	byte[] result = new byte[length];
	try
	{
	    for (int i = 0; i < length; i++)
		result[i] = (byte) (in[i + offset] ^ keystream.nextByte());
	}
	catch (LimitReachedException wontHappen)
	{
	}
	return result;
    }

    @Override
    protected int engineUpdate(byte[] in, int inOffset, int length, byte[] out, int outOffset) throws ShortBufferException
    {
	if (length < 0 || inOffset < 0 || length + inOffset > in.length
		|| outOffset < 0)
	    throw new ArrayIndexOutOfBoundsException();
	if (outOffset + length > out.length)
	    throw new ShortBufferException();
	try
	{
	    for (int i = 0; i < length; i++)
		out[i + outOffset] = (byte) (in[i + inOffset]
			^ keystream.nextByte());
	}
	catch (LimitReachedException wontHappen)
	{
	}
	return length;
    }
}
