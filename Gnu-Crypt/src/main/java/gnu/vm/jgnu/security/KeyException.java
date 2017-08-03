/* KeyException.java -- Thrown when there is a problem with a key
   Copyright (C) 1998, 2002, 2005, 2006  Free Software Foundation, Inc.

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

package gnu.vm.jgnu.security;

import gnu.vm.jgnu.security.GeneralSecurityException;
import gnu.vm.jgnu.security.Key;

/**
 * This exception is thrown when there is a problem with a key.
 *
 * @author Aaron M. Renn (arenn@urbanophile.com)
 * @see Key
 * @status updated to 1.4
 */
public class KeyException extends GeneralSecurityException
{
    /**
     * Compatible with JDK 1.1+.
     */
    private static final long serialVersionUID = -7483676942812432108L;

    /**
     * This method initializes a new instance of <code>KeyException</code> with
     * no descriptive message.
     */
    public KeyException()
    {
    }

    /**
     * This method initializes a new instance of <code>KeyException</code> with
     * a descriptive message.
     *
     * @param msg
     *            the descriptive message
     */
    public KeyException(String msg)
    {
	super(msg);
    }

    /**
     * Create a new instance with a descriptive error message and a cause.
     * 
     * @param s
     *            the descriptive error message
     * @param cause
     *            the cause
     * @since 1.5
     */
    public KeyException(String s, Throwable cause)
    {
	super(s, cause);
    }

    /**
     * Create a new instance with a cause.
     * 
     * @param cause
     *            the cause
     * @since 1.5
     */
    public KeyException(Throwable cause)
    {
	super(cause);
    }
}
