/* CipherInputStream.java -- Filters input through a cipher.
   Copyright (C) 2004  Free Software Foundation, Inc.

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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.Cipher;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NullCipher;
import gnu.vm.jgnux.crypto.ShortBufferException;

/**
 * This is an {@link java.io.InputStream} that filters its data through a
 * {@link Cipher} before returning it. The <code>Cipher</code> argument must
 * have been initialized before it is passed to the constructor.
 *
 * @author Casey Marshall (csm@gnu.org)
 */
public class CipherInputStream extends FilterInputStream
{

    // Constants and variables.
    // ------------------------------------------------------------------------

    /**
     * The underlying {@link Cipher} instance.
     */
    private final Cipher cipher;

    /**
     * Data that has been transformed but not read.
     */
    private byte[] outBuffer;

    /**
     * The offset into {@link #outBuffer} where valid data starts.
     */
    private int outOffset;

    /**
     * We set this when the cipher block size is 1, meaning that we can
     * transform any amount of data.
     */
    private final boolean isStream;

    /**
     * Whether or not we've reached the end of the stream.
     */
    private boolean eof;

    // Constructors.
    // ------------------------------------------------------------------------

    /**
     * Creates a new input stream without a cipher. This constructor is
     * <code>protected</code> because this class does not work without an
     * underlying cipher.
     *
     * @param in
     *            The underlying input stream.
     */
    protected CipherInputStream(InputStream in)
    {
	this(in, new NullCipher());
    }

    /**
     * Creates a new input stream with a source input stream and cipher.
     *
     * @param in
     *            The underlying input stream.
     * @param cipher
     *            The cipher to filter data through.
     */
    public CipherInputStream(InputStream in, Cipher cipher)
    {
	super(in);
	this.cipher = cipher;
	isStream = cipher.getBlockSize() == 1;
	eof = false;
    }

    // Instance methods overriding java.io.FilterInputStream.
    // ------------------------------------------------------------------------

    /**
     * Returns the number of bytes available without blocking. The value
     * returned is the number of bytes that have been processed by the cipher,
     * and which are currently buffered by this class.
     *
     * @return The number of bytes immediately available.
     * @throws java.io.IOException
     *             If an I/O exception occurs.
     */
    @Override
    public int available() throws IOException
    {
	if (isStream)
	    return super.available();
	if (outBuffer == null || outOffset >= outBuffer.length)
	    nextBlock();
	return outBuffer.length - outOffset;
    }

    /**
     * Close this input stream. This method merely calls the
     * {@link java.io.InputStream#close()} method of the underlying input
     * stream.
     *
     * @throws java.io.IOException
     *             If an I/O exception occurs.
     */
    @Override
    public synchronized void close() throws IOException
    {
	super.close();
    }

    /**
     * Set the mark. This method is unsupported and is empty.
     *
     * @param mark
     *            Is ignored.
     */
    @Override
    public void mark(int mark)
    {
    }

    /**
     * Returns whether or not this input stream supports the {@link #mark(long)}
     * and {@link #reset()} methods; this input stream does not, however, and
     * invariably returns <code>false</code>.
     *
     * @return <code>false</code>
     */
    @Override
    public boolean markSupported()
    {
	return false;
    }

    private void nextBlock() throws IOException
    {
	byte[] buf = new byte[cipher.getBlockSize()];

	try
	{
	    outBuffer = null;
	    outOffset = 0;
	    while (outBuffer == null)
	    {
		int l = in.read(buf);
		if (l == -1)
		{
		    outBuffer = cipher.doFinal();
		    eof = true;
		    return;
		}

		outOffset = 0;
		outBuffer = cipher.update(buf, 0, l);
	    }
	}
	catch (BadPaddingException bpe)
	{
	    IOException ioe = new IOException("bad padding");
	    ioe.initCause(bpe);
	    throw ioe;
	}
	catch (IllegalBlockSizeException ibse)
	{
	    IOException ioe = new IOException("illegal block size");
	    ioe.initCause(ibse);
	    throw ioe;
	}
    }

    /**
     * Read a single byte from this input stream; returns -1 on the end-of-file.
     *
     * @return The byte read, or -1 if there are no more bytes.
     * @throws java.io.IOExcpetion
     *             If an I/O exception occurs.
     */
    @Override
    public synchronized int read() throws IOException
    {
	if (isStream)
	{
	    byte[] buf = new byte[1];
	    int in = super.read();
	    if (in == -1)
		return -1;
	    buf[0] = (byte) in;
	    try
	    {
		cipher.update(buf, 0, 1, buf, 0);
	    }
	    catch (ShortBufferException shouldNotHappen)
	    {
		throw new IOException(shouldNotHappen.getMessage());
	    }
	    return buf[0] & 0xFF;
	}

	if (outBuffer == null || outOffset == outBuffer.length)
	{
	    if (eof)
		return -1;
	    nextBlock();
	}
	return outBuffer[outOffset++] & 0xFF;
    }

    /**
     * Read bytes into an array, returning the number of bytes read or -1 on the
     * end-of-file.
     *
     * @param buf
     *            The byte arry to read into.
     * @return The number of bytes read, or -1 on the end-of-file.
     * @throws java.io.IOException
     *             If an I/O exception occurs.
     */
    @Override
    public int read(byte[] buf) throws IOException
    {
	return read(buf, 0, buf.length);
    }

    /**
     * Read bytes into an array, returning the number of bytes read or -1 on the
     * end-of-file.
     *
     * @param buf
     *            The byte array to read into.
     * @param off
     *            The offset in <code>buf</code> to start.
     * @param len
     *            The maximum number of bytes to read.
     * @return The number of bytes read, or -1 on the end-of-file.
     * @throws java.io.IOException
     *             If an I/O exception occurs.
     */
    @Override
    public synchronized int read(byte[] buf, int off, int len) throws IOException
    {
	// CipherInputStream has this wierd implementation where if
	// the buffer is null, this call is the same as `skip'.
	if (buf == null)
	    return (int) skip(len);

	if (isStream)
	{
	    len = super.read(buf, off, len);
	    if (len > 0)
	    {
		try
		{
		    cipher.update(buf, off, len, buf, off);
		}
		catch (ShortBufferException shouldNotHappen)
		{
		    IOException ioe = new IOException(
			    "Short buffer for stream cipher -- this should not happen");
		    ioe.initCause(shouldNotHappen);
		    throw ioe;
		}
	    }
	    return len;
	}

	int count = 0;
	while (count < len)
	{
	    if (outBuffer == null || outOffset >= outBuffer.length)
	    {
		if (eof)
		{
		    if (count == 0)
			count = -1;
		    break;
		}
		nextBlock();
	    }
	    int l = Math.min(outBuffer.length - outOffset, len - count);
	    System.arraycopy(outBuffer, outOffset, buf, count + off, l);
	    count += l;
	    outOffset += l;
	}
	return count;
    }

    /**
     * Reset to the mark. This method is unsupported and is empty.
     */
    @Override
    public void reset() throws IOException
    {
	throw new IOException("reset not supported");
    }

    // Own methods.
    // -------------------------------------------------------------------------

    // FIXME: I don't fully understand how this class is supposed to work.

    /**
     * Skip a number of bytes. This class only supports skipping as many bytes
     * as are returned by {@link #available()}, which is the number of
     * transformed bytes currently in this class's internal buffer.
     *
     * @param bytes
     *            The number of bytes to skip.
     * @return The number of bytes skipped.
     */
    @Override
    public long skip(long bytes) throws IOException
    {
	if (isStream)
	{
	    return super.skip(bytes);
	}
	long ret = 0;
	if (bytes > 0 && outBuffer != null && outOffset >= outBuffer.length)
	{
	    ret = outBuffer.length - outOffset;
	    outOffset = outBuffer.length;
	}
	return ret;
    }
}
