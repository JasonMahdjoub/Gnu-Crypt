/* X509CRLEntry.java -- an entry in a X.509 CRL.
   Copyright (C) 2003, 2004, 2010  Free Software Foundation, Inc.

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

package gnu.jgnu.security.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import gnu.jgnu.security.OID;
import gnu.jgnu.security.der.DERReader;
import gnu.jgnu.security.der.DERValue;
import gnu.jgnu.security.x509.ext.Extension;
import gnu.vm.jgnu.security.cert.CRLException;

/**
 * A single entry in a X.509 certificate revocation list.
 *
 * @see X509CRL
 * @author Casey Marshall
 */
class X509CRLEntry extends gnu.vm.jgnu.security.cert.X509CRLEntry implements GnuPKIExtension {

	/** The DER encoded form of this CRL entry. */
	private byte[] encoded;

	/** The revoked certificate's serial number. */
	private BigInteger serialNo;

	/** The date the certificate was revoked. */
	private Date revocationDate;

	/** The CRL entry extensions. */
	private HashMap<OID, Extension> extensions;

	// Constructor.
	// ------------------------------------------------------------------------

	/**
	 * Create a new X.509 certificate revocation list entry from the given input
	 * stream and CRL version number.
	 *
	 * @param version
	 *            The CRL version.
	 * @param encoded
	 *            The stream of DER bytes.
	 * @throws CRLException
	 *             If the ASN.1 structure is invalid.
	 * @throws IOException
	 *             If the bytes cannot be read.
	 */
	X509CRLEntry(int version, DERReader encoded) throws CRLException, IOException {
		super();
		extensions = new HashMap<>();
		try {
			parse(version, encoded);
		} catch (IOException ioe) {
			throw ioe;
		} catch (Exception x) {
			throw new CRLException(x.toString());
		}
	}

	// X509CRLEntry methods.
	// ------------------------------------------------------------------------

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof X509CRLEntry))
			return false;
		return ((X509CRLEntry) o).getSerialNumber().equals(serialNo)
				&& ((X509CRLEntry) o).getRevocationDate().equals(revocationDate);
	}

	@Override
	public Set<String> getCriticalExtensionOIDs() {
		HashSet<String> s = new HashSet<>();
		for (Iterator<Extension> it = extensions.values().iterator(); it.hasNext();) {
			Extension e = it.next();
			if (e.isCritical())
				s.add(e.getOid().toString());
		}
		return Collections.unmodifiableSet(s);
	}

	@Override
	public byte[] getEncoded() {
		return encoded.clone();
	}

	@Override
	public Extension getExtension(OID oid) {
		return extensions.get(oid);
	}

	@Override
	public Collection<Extension> getExtensions() {
		return extensions.values();
	}

	@Override
	public byte[] getExtensionValue(String oid) {
		Extension e = getExtension(new OID(oid));
		if (e != null) {
			return e.getValue().getEncoded();
		}
		return null;
	}

	@Override
	public Set<String> getNonCriticalExtensionOIDs() {
		HashSet<String> s = new HashSet<>();
		for (Iterator<Extension> it = extensions.values().iterator(); it.hasNext();) {
			Extension e = it.next();
			if (!e.isCritical())
				s.add(e.getOid().toString());
		}
		return Collections.unmodifiableSet(s);
	}

	// X509Extension methods.
	// -------------------------------------------------------------------------

	@Override
	public Date getRevocationDate() {
		return (Date) revocationDate.clone();
	}

	@Override
	public BigInteger getSerialNumber() {
		return serialNo;
	}

	@Override
	public boolean hasExtensions() {
		return !extensions.isEmpty();
	}

	@Override
	public int hashCode() {
		return serialNo.hashCode();
	}

	// GnuPKIExtension method.
	// -------------------------------------------------------------------------

	@Override
	public boolean hasUnsupportedCriticalExtension() {
		for (Iterator<Extension> it = extensions.values().iterator(); it.hasNext();) {
			Extension e = it.next();
			if (e.isCritical() && !e.isSupported())
				return true;
		}
		return false;
	}

	private void parse(int version, DERReader der) throws Exception {
		// RevokedCertificate ::= SEQUENCE {
		DERValue entry = der.read();
		if (!entry.isConstructed())
			throw new IOException("malformed revokedCertificate");
		encoded = entry.getEncoded();
		int len = 0;

		// userCertificate CertificateSerialNumber,
		DERValue val = der.read();
		serialNo = (BigInteger) val.getValue();
		len += val.getEncodedLength();

		// revocationDate Time,
		val = der.read();
		revocationDate = (Date) val.getValue();
		len += val.getEncodedLength();
		// crlEntryExtensions Extensions OPTIONAL
		// -- if present MUST be v2
		if (len < entry.getLength()) {
			if (version < 2)
				throw new IOException("extra data in CRL entry");
			DERValue exts = der.read();
			if (!exts.isConstructed())
				throw new IOException("malformed Extensions");
			len = 0;
			while (len < exts.getLength()) {
				val = der.read();
				if (!val.isConstructed())
					throw new IOException("malformed Extension");
				Extension e = new Extension(val.getEncoded());
				extensions.put(e.getOid(), e);
				der.skip(val.getLength());
				len += val.getEncodedLength();
			}
		}
	}

	// Own methods.
	// -------------------------------------------------------------------------

	@Override
	public String toString() {
		return "X509CRLEntry serial=" + serialNo + " revocation date=" + revocationDate + " ext=" + extensions;
	}
}
