/* X509CRL.java -- X.509 certificate revocation list.
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
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import gnu.jgnu.security.OID;
import gnu.jgnu.security.der.BitString;
import gnu.jgnu.security.der.DER;
import gnu.jgnu.security.der.DERReader;
import gnu.jgnu.security.der.DERValue;
import gnu.jgnu.security.x509.ext.Extension;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.Principal;
import gnu.vm.jgnu.security.PublicKey;
import gnu.vm.jgnu.security.Signature;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.cert.CRLException;
import gnu.vm.jgnu.security.cert.Certificate;

/**
 * X.509 certificate revocation lists.
 *
 * @author Casey Marshall (rsdio@metastatic.org)
 */
public class X509CRL extends gnu.vm.jgnu.security.cert.X509CRL implements GnuPKIExtension
{

    // private static final OID ID_DSA = new OID("1.2.840.10040.4.1");
    private static final OID ID_DSA_WITH_SHA1 = new OID("1.2.840.10040.4.3");

    // private static final OID ID_RSA = new OID("1.2.840.113549.1.1.1");
    private static final OID ID_RSA_WITH_MD2 = new OID("1.2.840.113549.1.1.2");

    private static final OID ID_RSA_WITH_MD5 = new OID("1.2.840.113549.1.1.4");

    private static final OID ID_RSA_WITH_SHA1 = new OID("1.2.840.113549.1.1.5");

    private byte[] encoded;

    private byte[] tbsCRLBytes;

    private int version;

    // private OID algId;
    // private byte[] algParams;
    private Date thisUpdate;

    private Date nextUpdate;

    private X500DistinguishedName issuerDN;

    private HashMap<BigInteger, gnu.vm.jgnu.security.cert.X509CRLEntry> revokedCerts;

    private HashMap<OID, Extension> extensions;

    private OID sigAlg;

    private byte[] sigAlgParams;

    private byte[] rawSig;

    private byte[] signature;

    // Constructors.
    // ------------------------------------------------------------------------

    /**
     * Create a new X.509 CRL.
     *
     * @param encoded
     *            The DER encoded CRL.
     * @throws CRLException
     *             If the input bytes are incorrect.
     * @throws IOException
     *             If the input bytes cannot be read.
     */
    public X509CRL(InputStream encoded) throws CRLException, IOException
    {
	super();
	revokedCerts = new HashMap<>();
	extensions = new HashMap<>();
	try
	{
	    parse(encoded);
	}
	catch (IOException ioe)
	{
	    ioe.printStackTrace();
	    throw ioe;
	}
	catch (Exception x)
	{
	    x.printStackTrace();
	    throw new CRLException(x.toString());
	}
    }

    // X509CRL methods.
    // ------------------------------------------------------------------------

    private void doVerify(Signature sig, PublicKey key) throws CRLException, InvalidKeyException, SignatureException
    {
	sig.initVerify(key);
	sig.update(tbsCRLBytes);
	if (!sig.verify(signature))
	    throw new CRLException("signature not verified");
    }

    @Override
    public boolean equals(Object o)
    {
	if (!(o instanceof X509CRL))
	    return false;
	return ((X509CRL) o).getRevokedCertificates()
		.equals(revokedCerts.values());
    }

    @Override
    public Set<String> getCriticalExtensionOIDs()
    {
	HashSet<String> s = new HashSet<>();
	for (Iterator<Extension> it = extensions.values().iterator(); it
		.hasNext();)
	{
	    Extension e = it.next();
	    if (e.isCritical())
		s.add(e.getOid().toString());
	}
	return Collections.unmodifiableSet(s);
    }

    @Override
    public byte[] getEncoded()
    {
	return encoded.clone();
    }

    @Override
    public Extension getExtension(OID oid)
    {
	return extensions.get(oid);
    }

    @Override
    public Collection<Extension> getExtensions()
    {
	return extensions.values();
    }

    @Override
    public byte[] getExtensionValue(String oid)
    {
	Extension e = getExtension(new OID(oid));
	if (e != null)
	{
	    return e.getValue().getEncoded();
	}
	return null;
    }

    @Override
    public Principal getIssuerDN()
    {
	return issuerDN;
    }

    @Override
    public X500Principal getIssuerX500Principal()
    {
	return new X500Principal(issuerDN.getDer());
    }

    @Override
    public Date getNextUpdate()
    {
	if (nextUpdate != null)
	    return (Date) nextUpdate.clone();
	return null;
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs()
    {
	HashSet<String> s = new HashSet<>();
	for (Iterator<Extension> it = extensions.values().iterator(); it
		.hasNext();)
	{
	    Extension e = it.next();
	    if (!e.isCritical())
		s.add(e.getOid().toString());
	}
	return Collections.unmodifiableSet(s);
    }

    @Override
    public gnu.vm.jgnu.security.cert.X509CRLEntry getRevokedCertificate(BigInteger serialNo)
    {
	return revokedCerts.get(serialNo);
    }

    @Override
    public Set<gnu.vm.jgnu.security.cert.X509CRLEntry> getRevokedCertificates()
    {
	return Collections
		.unmodifiableSet(new HashSet<>(revokedCerts.values()));
    }

    @Override
    public String getSigAlgName()
    {
	if (sigAlg.equals(ID_DSA_WITH_SHA1))
	    return "SHA1withDSA";
	if (sigAlg.equals(ID_RSA_WITH_MD2))
	    return "MD2withRSA";
	if (sigAlg.equals(ID_RSA_WITH_MD5))
	    return "MD5withRSA";
	if (sigAlg.equals(ID_RSA_WITH_SHA1))
	    return "SHA1withRSA";
	return "unknown";
    }

    @Override
    public String getSigAlgOID()
    {
	return sigAlg.toString();
    }

    @Override
    public byte[] getSigAlgParams()
    {
	if (sigAlgParams != null)
	    return sigAlgParams.clone();
	return null;
    }

    @Override
    public byte[] getSignature()
    {
	return rawSig.clone();
    }

    // X509Extension methods.
    // ------------------------------------------------------------------------

    @Override
    public byte[] getTBSCertList()
    {
	return tbsCRLBytes.clone();
    }

    @Override
    public Date getThisUpdate()
    {
	return (Date) thisUpdate.clone();
    }

    @Override
    public int getVersion()
    {
	return version;
    }

    @Override
    public int hashCode()
    {
	return revokedCerts.hashCode();
    }

    // GnuPKIExtension method.
    // -------------------------------------------------------------------------

    @Override
    public boolean hasUnsupportedCriticalExtension()
    {
	for (Iterator<Extension> it = extensions.values().iterator(); it
		.hasNext();)
	{
	    Extension e = it.next();
	    if (e.isCritical() && !e.isSupported())
		return true;
	}
	return false;
    }

    @Override
    public boolean isRevoked(Certificate cert)
    {
	if (!(cert instanceof gnu.vm.jgnu.security.cert.X509Certificate))
	    throw new IllegalArgumentException("not a X.509 certificate");
	BigInteger certSerial = ((gnu.vm.jgnu.security.cert.X509Certificate) cert)
		.getSerialNumber();
	X509CRLEntry ent = (X509CRLEntry) revokedCerts.get(certSerial);
	if (ent == null)
	    return false;
	return ent.getRevocationDate().compareTo(new Date()) < 0;
    }

    // CRL methods.
    // -------------------------------------------------------------------------

    private void parse(InputStream in) throws Exception
    {
	// CertificateList ::= SEQUENCE {
	DERReader der = new DERReader(in);
	DERValue val = der.read();
	if (!val.isConstructed())
	    throw new IOException("malformed CertificateList");
	encoded = val.getEncoded();

	// tbsCertList ::= SEQUENCE { -- TBSCertList
	val = der.read();
	if (!val.isConstructed())
	    throw new IOException("malformed TBSCertList");
	tbsCRLBytes = val.getEncoded();

	// version Version OPTIONAL,
	// -- If present must be v2
	val = der.read();
	if (val.getValue() instanceof BigInteger)
	{
	    version = ((BigInteger) val.getValue()).intValue() + 1;
	    val = der.read();
	}
	else
	    version = 1;

	// signature AlgorithmIdentifier,
	if (!val.isConstructed())
	    throw new IOException("malformed AlgorithmIdentifier");
	DERValue algIdVal = der.read();
	// algId = (OID) algIdVal.getValue();
	if (val.getLength() > algIdVal.getEncodedLength())
	{
	    val = der.read();
	    // algParams = val.getEncoded();
	    if (val.isConstructed())
		in.skip(val.getLength());
	}

	// issuer Name,
	val = der.read();
	issuerDN = new X500DistinguishedName(val.getEncoded());
	der.skip(val.getLength());

	// thisUpdate Time,
	thisUpdate = (Date) der.read().getValue();

	// nextUpdate Time OPTIONAL,
	val = der.read();
	if (val.getValue() instanceof Date)
	{
	    nextUpdate = (Date) val.getValue();
	    val = der.read();
	}

	// revokedCertificates SEQUENCE OF SEQUENCE {
	// -- X509CRLEntry objects...
	// } OPTIONAL,
	if (val.getTag() != 0)
	{
	    int len = 0;
	    while (len < val.getLength())
	    {
		X509CRLEntry entry = new X509CRLEntry(version, der);
		revokedCerts.put(entry.getSerialNumber(), entry);
		len += entry.getEncoded().length;
	    }
	    val = der.read();
	}

	// crlExtensions [0] EXPLICIT Extensions OPTIONAL
	// -- if present MUST be v2
	if (val.getTagClass() != DER.UNIVERSAL && val.getTag() == 0)
	{
	    if (version < 2)
		throw new IOException("extra data in CRL");
	    DERValue exts = der.read();
	    if (!exts.isConstructed())
		throw new IOException("malformed Extensions");
	    int len = 0;
	    while (len < exts.getLength())
	    {
		DERValue ext = der.read();
		if (!ext.isConstructed())
		    throw new IOException("malformed Extension");
		Extension e = new Extension(ext.getEncoded());
		extensions.put(e.getOid(), e);
		der.skip(ext.getLength());
		len += ext.getEncodedLength();
	    }
	    val = der.read();
	}

	if (!val.isConstructed())
	    throw new IOException("malformed AlgorithmIdentifier");
	DERValue sigAlgVal = der.read();
	if (sigAlgVal.getTag() != DER.OBJECT_IDENTIFIER)
	    throw new IOException("malformed AlgorithmIdentifier");
	sigAlg = (OID) sigAlgVal.getValue();
	if (val.getLength() > sigAlgVal.getEncodedLength())
	{
	    val = der.read();
	    sigAlgParams = val.getEncoded();
	    if (val.isConstructed())
		in.skip(val.getLength());
	}
	val = der.read();
	rawSig = val.getEncoded();
	signature = ((BitString) val.getValue()).toByteArray();
    }

    @Override
    public String toString()
    {
	return X509CRL.class.getName();
    }

    // Own methods.
    // ------------------------------------------------------------------------

    @Override
    public void verify(PublicKey key) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
	Signature sig = Signature.getInstance(sigAlg.toString());
	doVerify(sig, key);
    }

    @Override
    public void verify(PublicKey key, String provider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
	Signature sig = Signature.getInstance(sigAlg.toString(), provider);
	doVerify(sig, key);
    }
}
