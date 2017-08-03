/* CollectionCertStore.java -- Collection-based cert store.
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

package gnu.jgnu.security.provider;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.cert.CRL;
import gnu.vm.jgnu.security.cert.CRLSelector;
import gnu.vm.jgnu.security.cert.CertSelector;
import gnu.vm.jgnu.security.cert.CertStoreParameters;
import gnu.vm.jgnu.security.cert.CertStoreSpi;
import gnu.vm.jgnu.security.cert.Certificate;
import gnu.vm.jgnu.security.cert.CollectionCertStoreParameters;

public final class CollectionCertStoreImpl extends CertStoreSpi
{

    // Fields.
    // -------------------------------------------------------------------------

    private final Collection<?> store;

    // Constructors.
    // -------------------------------------------------------------------------

    public CollectionCertStoreImpl(CertStoreParameters params) throws InvalidAlgorithmParameterException
    {
	super(params);
	if (!(params instanceof CollectionCertStoreParameters))
	    throw new InvalidAlgorithmParameterException(
		    "not a CollectionCertStoreParameters object");
	store = ((CollectionCertStoreParameters) params).getCollection();
    }

    // Instance methods.
    // -------------------------------------------------------------------------

    @Override
    public Collection<Certificate> engineGetCertificates(CertSelector selector)
    {
	LinkedList<Certificate> result = new LinkedList<>();
	for (Iterator<?> it = store.iterator(); it.hasNext();)
	{
	    Object o = it.next();
	    if ((o instanceof Certificate) && selector.match((Certificate) o))
		result.add((Certificate) o);
	}
	return result;
    }

    @Override
    public Collection<CRL> engineGetCRLs(CRLSelector selector)
    {
	LinkedList<CRL> result = new LinkedList<>();
	for (Iterator<?> it = store.iterator(); it.hasNext();)
	{
	    Object o = it.next();
	    if ((o instanceof CRL) && selector.match((CRL) o))
		result.add((CRL) o);
	}
	return result;
    }
}
