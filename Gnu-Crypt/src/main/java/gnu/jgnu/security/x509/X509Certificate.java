/* X509Certificate.java -- X.509 certificate.
   Copyright (C) 2003, 2004, 2006  Free Software Foundation, Inc.

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
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import gnu.jgnu.security.OID;
import gnu.jgnu.security.der.BitString;
import gnu.jgnu.security.der.DER;
import gnu.jgnu.security.der.DERReader;
import gnu.jgnu.security.der.DERValue;
import gnu.jgnu.security.x509.ext.BasicConstraints;
import gnu.jgnu.security.x509.ext.ExtendedKeyUsage;
import gnu.jgnu.security.x509.ext.Extension;
import gnu.jgnu.security.x509.ext.GeneralName;
import gnu.jgnu.security.x509.ext.IssuerAlternativeNames;
import gnu.jgnu.security.x509.ext.KeyUsage;
import gnu.jgnu.security.x509.ext.SubjectAlternativeNames;
import gnu.vm.jgnu.security.AlgorithmParameters;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.KeyFactory;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.Principal;
import gnu.vm.jgnu.security.PublicKey;
import gnu.vm.jgnu.security.Signature;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.cert.CertificateException;
import gnu.vm.jgnu.security.cert.CertificateExpiredException;
import gnu.vm.jgnu.security.cert.CertificateNotYetValidException;
import gnu.vm.jgnu.security.interfaces.DSAParams;
import gnu.vm.jgnu.security.interfaces.DSAPublicKey;
import gnu.vm.jgnu.security.spec.DSAParameterSpec;
import gnu.vm.jgnu.security.spec.X509EncodedKeySpec;
import gnu.vm.jgnux.security.auth.x500.X500Principal;

/**
 * An implementation of X.509 certificates.
 *
 * @author Casey Marshall (rsdio@metastatic.org)
 */
public class X509Certificate extends gnu.vm.jgnu.security.cert.X509Certificate implements Serializable, GnuPKIExtension
{

    // Constants and fields.
    // ------------------------------------------------------------------------

    private static final long serialVersionUID = -2491127588187038216L;

    protected static final OID ID_DSA = new OID("1.2.840.10040.4.1");

    protected static final OID ID_DSA_WITH_SHA1 = new OID("1.2.840.10040.4.3");

    protected static final OID ID_RSA = new OID("1.2.840.113549.1.1.1");

    protected static final OID ID_RSA_WITH_MD2 = new OID(
	    "1.2.840.113549.1.1.2");

    protected static final OID ID_RSA_WITH_MD5 = new OID(
	    "1.2.840.113549.1.1.4");

    protected static final OID ID_RSA_WITH_SHA1 = new OID(
	    "1.2.840.113549.1.1.5");

    protected static final OID ID_ECDSA_WITH_SHA1 = new OID(
	    "1.2.840.10045.4.1");

    // This object SHOULD be serialized with an instance of
    // java.security.cert.Certificate.CertificateRep, thus all fields are
    // transient.

    // The encoded certificate.
    protected transient byte[] encoded;

    // TBSCertificate part.
    protected transient byte[] tbsCertBytes;

    protected transient int version;

    protected transient BigInteger serialNo;

    protected transient OID algId;

    protected transient byte[] algVal;

    protected transient X500DistinguishedName issuer;

    protected transient Date notBefore;

    protected transient Date notAfter;

    protected transient X500DistinguishedName subject;

    protected transient PublicKey subjectKey;

    protected transient BitString issuerUniqueId;

    protected transient BitString subjectUniqueId;

    protected transient Map<OID, Extension> extensions;

    // Signature.
    protected transient OID sigAlgId;

    protected transient byte[] sigAlgVal;

    protected transient byte[] signature;

    // Constructors.
    // ------------------------------------------------------------------------

    protected X509Certificate()
    {
	extensions = new HashMap<OID, Extension>();
    }

    /**
     * Create a new X.509 certificate from the encoded data. The input data are
     * expected to be the ASN.1 DER encoding of the certificate.
     *
     * @param encoded
     *            The encoded certificate data.
     * @throws IOException
     *             If the certificate cannot be read, possibly from a formatting
     *             error.
     * @throws CertificateException
     *             If the data read is not an X.509 certificate.
     */
    public X509Certificate(InputStream encoded) throws CertificateException, IOException
    {
	super();
	extensions = new HashMap<OID, Extension>();
	try
	{
	    parse(encoded);
	}
	catch (IOException ioe)
	{
	    throw ioe;
	}
	catch (Exception e)
	{
	    CertificateException ce = new CertificateException(e.getMessage());
	    ce.initCause(e);
	    throw ce;
	}
    }

    // X509Certificate methods.
    // ------------------------------------------------------------------------

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException
    {
	checkValidity(new Date());
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException
    {
	if (date.compareTo(notBefore) < 0)
	{
	    throw new CertificateNotYetValidException();
	}
	if (date.compareTo(notAfter) > 0)
	{
	    throw new CertificateExpiredException();
	}
    }

    /**
     * Verify this certificate's signature.
     */
    private void doVerify(Signature sig, PublicKey key) throws CertificateException, InvalidKeyException, SignatureException
    {
	sig.initVerify(key);
	sig.update(tbsCertBytes);
	if (!sig.verify(signature))
	{
	    throw new CertificateException("signature not validated");
	}
    }

    @Override
    public boolean equals(Object other)
    {
	if (!(other instanceof X509Certificate))
	    return false;
	if (other instanceof X509Certificate)
	    return Arrays.equals(encoded, ((X509Certificate) other).encoded);
	byte[] enc = ((X509Certificate) other).getEncoded();
	if (enc == null)
	    return false;
	return Arrays.equals(encoded, enc);
    }

    @Override
    public int getBasicConstraints()
    {
	Extension e = getExtension(BasicConstraints.ID);
	if (e != null)
	{
	    return ((BasicConstraints) e.getValue()).getPathLengthConstraint();
	}
	return -1;
    }

    @Override
    public Set<String> getCriticalExtensionOIDs()
    {
	HashSet<String> s = new HashSet<String>();
	for (Extension e : extensions.values())
	{
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
    public List<String> getExtendedKeyUsage()
    {
	Extension e = getExtension(ExtendedKeyUsage.ID);
	if (e != null)
	{
	    List<OID> a = ((ExtendedKeyUsage) e.getValue()).getPurposeIds();
	    List<String> b = new ArrayList<String>(a.size());
	    for (OID oid : a)
		b.add(oid.toString());
	    return Collections.unmodifiableList(b);
	}
	return null;
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
    public Collection<List<?>> getIssuerAlternativeNames()
    {
	Extension e = getExtension(IssuerAlternativeNames.ID);
	if (e != null)
	{
	    List<GeneralName> names = ((IssuerAlternativeNames) e.getValue())
		    .getNames();
	    List<List<?>> list = new ArrayList<List<?>>(names.size());
	    for (GeneralName name : names)
	    {
		List<Object> n = new ArrayList<Object>(2);
		n.add(new Integer(name.kind().tag()));
		n.add(name.name());
		list.add(n);
	    }
	    return list;
	}
	return null;
    }

    @Override
    public Principal getIssuerDN()
    {
	return issuer;
    }

    @Override
    public boolean[] getIssuerUniqueID()
    {
	if (issuerUniqueId != null)
	{
	    return issuerUniqueId.toBooleanArray();
	}
	return null;
    }

    @Override
    public X500Principal getIssuerX500Principal()
    {
	return new X500Principal(issuer.getDer());
    }

    @Override
    public boolean[] getKeyUsage()
    {
	Extension e = getExtension(KeyUsage.ID);
	if (e != null)
	{
	    KeyUsage ku = (KeyUsage) e.getValue();
	    boolean[] result = new boolean[9];
	    boolean[] b = ku.getKeyUsage().toBooleanArray();
	    System.arraycopy(b, 0, result, 0, b.length);
	    return result;
	}
	return null;
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs()
    {
	HashSet<String> s = new HashSet<String>();
	for (Extension e : extensions.values())
	{
	    if (!e.isCritical())
		s.add(e.getOid().toString());
	}
	return Collections.unmodifiableSet(s);
    }

    @Override
    public Date getNotAfter()
    {
	return (Date) notAfter.clone();
    }

    @Override
    public Date getNotBefore()
    {
	return (Date) notBefore.clone();
    }

    @Override
    public PublicKey getPublicKey()
    {
	return subjectKey;
    }

    @Override
    public BigInteger getSerialNumber()
    {
	return serialNo;
    }

    @Override
    public String getSigAlgName()
    {
	if (sigAlgId.equals(ID_DSA_WITH_SHA1))
	{
	    return "SHA1withDSA";
	}
	if (sigAlgId.equals(ID_RSA_WITH_MD2))
	{
	    return "MD2withRSA";
	}
	if (sigAlgId.equals(ID_RSA_WITH_MD5))
	{
	    return "MD5withRSA";
	}
	if (sigAlgId.equals(ID_RSA_WITH_SHA1))
	{
	    return "SHA1withRSA";
	}
	return "unknown";
    }

    // X509Extension methods.
    // ------------------------------------------------------------------------

    @Override
    public String getSigAlgOID()
    {
	return sigAlgId.toString();
    }

    @Override
    public byte[] getSigAlgParams()
    {
	return sigAlgVal.clone();
    }

    @Override
    public byte[] getSignature()
    {
	return signature.clone();
    }

    @Override
    public Collection<List<?>> getSubjectAlternativeNames()
    {
	Extension e = getExtension(SubjectAlternativeNames.ID);
	if (e != null)
	{
	    List<GeneralName> names = ((SubjectAlternativeNames) e.getValue())
		    .getNames();
	    List<List<?>> list = new ArrayList<List<?>>(names.size());
	    for (GeneralName name : names)
	    {
		List<Object> n = new ArrayList<Object>(2);
		n.add(new Integer(name.kind().tag()));
		n.add(name.name());
		list.add(n);
	    }
	    return list;
	}
	return null;
    }

    // GnuPKIExtension method.
    // -------------------------------------------------------------------------

    @Override
    public Principal getSubjectDN()
    {
	return subject;
    }

    @Override
    public boolean[] getSubjectUniqueID()
    {
	if (subjectUniqueId != null)
	{
	    return subjectUniqueId.toBooleanArray();
	}
	return null;
    }

    // Certificate methods.
    // -------------------------------------------------------------------------

    @Override
    public X500Principal getSubjectX500Principal()
    {
	return new X500Principal(subject.getDer());
    }

    @Override
    public byte[] getTBSCertificate()
    {
	return tbsCertBytes.clone();
    }

    @Override
    public int getVersion()
    {
	return version;
    }

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

    /**
     * Parse a DER stream into an X.509 certificate.
     *
     * @param encoded
     *            The encoded bytes.
     */
    private void parse(InputStream encoded) throws Exception
    {
	DERReader der = new DERReader(encoded);

	// Certificate ::= SEQUENCE {
	DERValue cert = der.read();

	this.encoded = cert.getEncoded();
	if (!cert.isConstructed())
	{
	    throw new IOException("malformed Certificate");
	}

	// TBSCertificate ::= SEQUENCE {
	DERValue tbsCert = der.read();
	if (tbsCert.getValue() != DER.CONSTRUCTED_VALUE)
	{
	    throw new IOException("malformed TBSCertificate");
	}
	tbsCertBytes = tbsCert.getEncoded();

	// Version ::= INTEGER [0] { v1(0), v2(1), v3(2) }
	DERValue val = der.read();
	if (val.getTagClass() == DER.CONTEXT && val.getTag() == 0)
	{
	    version = ((BigInteger) der.read().getValue()).intValue() + 1;
	    val = der.read();
	}
	else
	{
	    version = 1;
	}

	// SerialNumber ::= INTEGER
	serialNo = (BigInteger) val.getValue();

	// AlgorithmIdentifier ::= SEQUENCE {
	val = der.read();
	if (!val.isConstructed())
	{
	    throw new IOException("malformed AlgorithmIdentifier");
	}
	int certAlgLen = val.getLength();
	val = der.read();

	// algorithm OBJECT IDENTIFIER,
	algId = (OID) val.getValue();

	// parameters ANY DEFINED BY algorithm OPTIONAL }
	if (certAlgLen > val.getEncodedLength())
	{
	    val = der.read();
	    if (val == null)
	    {
		algVal = null;
	    }
	    else
	    {
		algVal = val.getEncoded();

		if (val.isConstructed())
		    encoded.skip(val.getLength());
	    }
	}

	// issuer Name,
	val = der.read();
	issuer = new X500DistinguishedName(val.getEncoded());
	der.skip(val.getLength());

	// Validity ::= SEQUENCE {
	// notBefore Time,
	// notAfter Time }
	if (!der.read().isConstructed())
	{
	    throw new IOException("malformed Validity");
	}
	notBefore = (Date) der.read().getValue();
	notAfter = (Date) der.read().getValue();

	// subject Name,
	val = der.read();
	subject = new X500DistinguishedName(val.getEncoded());
	der.skip(val.getLength());

	// SubjectPublicKeyInfo ::= SEQUENCE {
	// algorithm AlgorithmIdentifier,
	// subjectPublicKey BIT STRING }
	DERValue spki = der.read();
	if (!spki.isConstructed())
	{
	    throw new IOException("malformed SubjectPublicKeyInfo");
	}
	KeyFactory spkFac = KeyFactory.getInstance("X.509");
	subjectKey = spkFac
		.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
	der.skip(spki.getLength());

	val = der.read();
	if (version >= 2 && val.getTagClass() != DER.UNIVERSAL
		&& val.getTag() == 1)
	{
	    byte[] b = (byte[]) val.getValue();
	    issuerUniqueId = new BitString(b, 1, b.length - 1, b[0] & 0xFF);
	    val = der.read();
	}
	if (version >= 2 && val.getTagClass() != DER.UNIVERSAL
		&& val.getTag() == 2)
	{
	    byte[] b = (byte[]) val.getValue();
	    subjectUniqueId = new BitString(b, 1, b.length - 1, b[0] & 0xFF);
	    val = der.read();
	}
	if (version >= 3 && val.getTagClass() != DER.UNIVERSAL
		&& val.getTag() == 3)
	{
	    val = der.read();
	    int len = 0;
	    while (len < val.getLength())
	    {
		DERValue ext = der.read();
		Extension e = new Extension(ext.getEncoded());
		extensions.put(e.getOid(), e);
		der.skip(ext.getLength());
		len += ext.getEncodedLength();
	    }

	    val = der.read();
	}

	if (!val.isConstructed())
	{
	    throw new CertificateException("malformed AlgorithmIdentifier");
	}
	int sigAlgLen = val.getLength();
	val = der.read();
	sigAlgId = (OID) val.getValue();
	if (sigAlgLen > val.getEncodedLength())
	{
	    val = der.read();
	    if (val.getValue() == null)
	    {
		if (subjectKey instanceof DSAPublicKey)
		{
		    AlgorithmParameters params = AlgorithmParameters
			    .getInstance("DSA");
		    DSAParams dsap = ((DSAPublicKey) subjectKey).getParams();
		    DSAParameterSpec spec = new DSAParameterSpec(dsap.getP(),
			    dsap.getQ(), dsap.getG());
		    params.init(spec);
		    sigAlgVal = params.getEncoded();
		}
	    }
	    else
	    {
		sigAlgVal = val.getEncoded();
	    }
	    if (val.isConstructed())
	    {
		encoded.skip(val.getLength());
	    }
	}
	signature = ((BitString) der.read().getValue()).toByteArray();
    }

    @Override
    public String toString()
    {
	StringWriter str = new StringWriter();
	PrintWriter out = new PrintWriter(str);
	out.println(X509Certificate.class.getName() + " {");
	out.println("  TBSCertificate {");
	out.println("    version = " + version + ";");
	out.println("    serialNo = " + serialNo + ";");
	out.println("    signature = {");
	out.println("      algorithm = " + getSigAlgName() + ";");
	out.print("      parameters =");
	if (sigAlgVal != null)
	{
	    out.println();
	    out.print(Util.hexDump(sigAlgVal, "        "));
	}
	else
	{
	    out.println(" null;");
	}
	out.println("    }");
	out.println("    issuer = " + issuer.getName() + ";");
	out.println("    validity = {");
	out.println("      notBefore = " + notBefore + ";");
	out.println("      notAfter  = " + notAfter + ";");
	out.println("    }");
	out.println("    subject = " + subject.getName() + ";");
	out.println("    subjectPublicKeyInfo = {");
	out.println("      algorithm = " + subjectKey.getAlgorithm());
	out.println("      key =");
	out.print(Util.hexDump(subjectKey.getEncoded(), "        "));
	out.println("    };");
	out.println("    issuerUniqueId  = " + issuerUniqueId + ";");
	out.println("    subjectUniqueId = " + subjectUniqueId + ";");
	out.println("    extensions = {");
	for (Iterator<Extension> it = extensions.values().iterator(); it
		.hasNext();)
	{
	    out.println("      " + it.next());
	}
	out.println("    }");
	out.println("  }");
	out.println("  signatureAlgorithm = " + getSigAlgName() + ";");
	out.println("  signatureValue =");
	out.print(Util.hexDump(signature, "    "));
	out.println("}");
	return str.toString();
    }

    // Own methods.
    // ------------------------------------------------------------------------

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
	Signature sig = Signature.getInstance(sigAlgId.toString());
	doVerify(sig, key);
    }

    @Override
    public void verify(PublicKey key, String provider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
    {
	Signature sig = Signature.getInstance(sigAlgId.toString(), provider);
	doVerify(sig, key);
    }
}
