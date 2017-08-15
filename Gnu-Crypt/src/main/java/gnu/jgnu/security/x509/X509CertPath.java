/* X509CertPath.java -- an X.509 certificate path.
   Copyright (C) 2004  Free Software Fonudation, Inc.

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import gnu.jgnu.security.OID;
import gnu.jgnu.security.der.DER;
import gnu.jgnu.security.der.DEREncodingException;
import gnu.jgnu.security.der.DERReader;
import gnu.jgnu.security.der.DERValue;
import gnu.vm.jgnu.security.cert.CertPath;
import gnu.vm.jgnu.security.cert.Certificate;
import gnu.vm.jgnu.security.cert.CertificateEncodingException;
import gnu.vm.jgnu.security.cert.CertificateException;

/**
 * A certificate path (or certificate chain) of X509Certificates.
 *
 * @author Casey Marshall (rsdio@metastatic.org)
 */
public class X509CertPath extends CertPath {

	// Fields.
	// -------------------------------------------------------------------------

	public static final List<String> ENCODINGS = Collections
			.unmodifiableList(Arrays.asList(new String[] { "PkiPath", "PKCS7" }));

	private static final OID PKCS7_SIGNED_DATA = new OID("1.2.840.113549.1.7.2");

	private static final OID PKCS7_DATA = new OID("1.2.840.113549.1.7.1");

	/** The certificate path. */
	private List<? extends Certificate> path;

	/** The cached PKCS #7 encoded bytes. */
	private byte[] pkcs_encoded;

	/** The cached PkiPath encoded bytes. */
	private byte[] pki_encoded;

	// Constructor.
	// -------------------------------------------------------------------------

	public X509CertPath(InputStream in) throws CertificateEncodingException {
		this(in, ENCODINGS.get(0));
	}

	public X509CertPath(InputStream in, String encoding) throws CertificateEncodingException {
		super("X.509");
		try {
			parse(in, encoding);
		} catch (IOException ioe) {
			throw new CertificateEncodingException();
		}
	}

	public X509CertPath(List<? extends Certificate> path) {
		super("X.509");
		this.path = Collections.unmodifiableList(path);
	}

	// Instance methods.
	// -------------------------------------------------------------------------

	private byte[] encodePKCS() throws CertificateEncodingException, IOException {
		synchronized (path) {
			ArrayList<DERValue> signedData = new ArrayList<>(5);
			signedData.add(new DERValue(DER.INTEGER, BigInteger.ONE));
			signedData.add(new DERValue(DER.CONSTRUCTED | DER.SET, Collections.EMPTY_SET));
			signedData.add(new DERValue(DER.CONSTRUCTED | DER.SEQUENCE,
					Collections.singletonList(new DERValue(DER.OBJECT_IDENTIFIER, PKCS7_DATA))));
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			for (Iterator<? extends Certificate> i = path.iterator(); i.hasNext();) {
				out.write(i.next().getEncoded());
			}
			byte[] b = out.toByteArray();
			signedData.add(new DERValue(DER.CONSTRUCTED | DER.CONTEXT, b.length, b, null));
			DERValue sdValue = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, signedData);

			ArrayList<DERValue> contentInfo = new ArrayList<>(2);
			contentInfo.add(new DERValue(DER.OBJECT_IDENTIFIER, PKCS7_SIGNED_DATA));
			contentInfo.add(new DERValue(DER.CONSTRUCTED | DER.CONTEXT, sdValue));
			return new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, contentInfo).getEncoded();
		}
	}

	private byte[] encodePki() throws CertificateEncodingException, IOException {
		synchronized (path) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			for (Iterator<? extends Certificate> i = path.iterator(); i.hasNext();) {
				out.write(i.next().getEncoded());
			}
			byte[] b = out.toByteArray();
			DERValue val = new DERValue(DER.CONSTRUCTED | DER.SEQUENCE, b.length, b, null);
			return val.getEncoded();
		}
	}

	@Override
	public List<? extends Certificate> getCertificates() {
		return path; // already unmodifiable
	}

	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		return getEncoded(ENCODINGS.get(0));
	}

	// Own methods.
	// -------------------------------------------------------------------------

	@Override
	public byte[] getEncoded(String encoding) throws CertificateEncodingException {
		if (encoding.equalsIgnoreCase("PkiPath")) {
			if (pki_encoded == null) {
				try {
					pki_encoded = encodePki();
				} catch (IOException ioe) {
					throw new CertificateEncodingException();
				}
			}
			return pki_encoded.clone();
		} else if (encoding.equalsIgnoreCase("PKCS7")) {
			if (pkcs_encoded == null) {
				try {
					pkcs_encoded = encodePKCS();
				} catch (IOException ioe) {
					throw new CertificateEncodingException();
				}
			}
			return pkcs_encoded.clone();
		} else
			throw new CertificateEncodingException("unknown encoding: " + encoding);
	}

	@Override
	public Iterator<String> getEncodings() {
		return ENCODINGS.iterator(); // already unmodifiable
	}

	private void parse(InputStream in, String encoding) throws CertificateEncodingException, IOException {
		DERReader der = new DERReader(in);
		DERValue path = null;
		if (encoding.equalsIgnoreCase("PkiPath")) {
			// PKI encoding is just a SEQUENCE of X.509 certificates.
			path = der.read();
			if (!path.isConstructed())
				throw new DEREncodingException("malformed PkiPath");
		} else if (encoding.equalsIgnoreCase("PKCS7")) {
			// PKCS #7 encoding means that the certificates are contained in a
			// SignedData PKCS #7 type.
			//
			// ContentInfo ::= SEQUENCE {
			// contentType ::= ContentType,
			// content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
			//
			// ContentType ::= OBJECT IDENTIFIER
			//
			// SignedData ::= SEQUENCE {
			// version Version,
			// digestAlgorithms DigestAlgorithmIdentifiers,
			// contentInfo ContentInfo,
			// certificates [0] IMPLICIT ExtendedCertificatesAndCertificates
			// OPTIONAL,
			// crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
			// signerInfos SignerInfos }
			//
			// Version ::= INTEGER
			//
			DERValue value = der.read();
			if (!value.isConstructed())
				throw new DEREncodingException("malformed ContentInfo");
			value = der.read();
			if (!(value.getValue() instanceof OID) || ((OID) value.getValue()).equals(PKCS7_SIGNED_DATA))
				throw new DEREncodingException("not a SignedData");
			value = der.read();
			if (!value.isConstructed() || value.getTag() != 0)
				throw new DEREncodingException("malformed content");
			value = der.read();
			if (value.getTag() != DER.INTEGER)
				throw new DEREncodingException("malformed Version");
			value = der.read();
			if (!value.isConstructed() || value.getTag() != DER.SET)
				throw new DEREncodingException("malformed DigestAlgorithmIdentifiers");
			der.skip(value.getLength());
			value = der.read();
			if (!value.isConstructed())
				throw new DEREncodingException("malformed ContentInfo");
			der.skip(value.getLength());
			path = der.read();
			if (!path.isConstructed() || path.getTag() != 0)
				throw new DEREncodingException("no certificates");
		} else
			throw new CertificateEncodingException("unknown encoding: " + encoding);

		LinkedList<X509Certificate> certs = new LinkedList<>();
		int len = 0;
		while (len < path.getLength()) {
			DERValue cert = der.read();
			try {
				certs.add(new X509Certificate(new ByteArrayInputStream(cert.getEncoded())));
			} catch (CertificateException ce) {
				throw new CertificateEncodingException(ce.getMessage());
			}
			len += cert.getEncodedLength();
			der.skip(cert.getLength());
		}

		this.path = Collections.unmodifiableList(certs);
	}
}
