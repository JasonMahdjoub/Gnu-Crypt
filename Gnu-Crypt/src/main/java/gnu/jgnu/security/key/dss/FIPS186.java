/* FIPS186.java --
   Copyright 2001, 2002, 2003, 2006 Free Software Foundation, Inc.

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

package gnu.jgnu.security.key.dss;

import java.math.BigInteger;

import gnu.jgnu.security.hash.Sha160;
import gnu.jgnu.security.util.PRNG;
import gnu.vm.jgnu.security.SecureRandom;

/**
 * An implementation of the DSA parameters generation as described in FIPS-186.
 * <p>
 * References:
 * <p>
 * <a href="http://www.itl.nist.gov/fipspubs/fip186.htm">Digital Signature
 * Standard (DSS)</a>, Federal Information Processing Standards Publication 186.
 * National Institute of Standards and Technology.
 */
public class FIPS186
{
    public static final int DSA_PARAMS_SEED = 0;

    public static final int DSA_PARAMS_COUNTER = 1;

    public static final int DSA_PARAMS_Q = 2;

    public static final int DSA_PARAMS_P = 3;

    public static final int DSA_PARAMS_E = 4;

    public static final int DSA_PARAMS_G = 5;

    /** The BigInteger constant 2. */
    private static final BigInteger TWO = BigInteger.valueOf(2L);

    private static final BigInteger TWO_POW_160 = TWO.pow(160);

    /** The SHA instance to use. */
    private Sha160 sha = new Sha160();

    /** The length of the modulus of DSS keys generated by this instance. */
    private int L;

    /** The optional {@link SecureRandom} instance to use. */
    private SecureRandom rnd = null;

    /** Our default source of randomness. */
    private PRNG prng = null;

    public FIPS186(int L, SecureRandom rnd)
    {
	super();

	this.L = L;
	this.rnd = rnd;
    }

    /**
     * This method generates the DSS <code>p</code>, <code>q</code>, and
     * <code>g</code> parameters only when <code>L</code> (the modulus length)
     * is not one of the following: <code>512</code>, <code>768</code> and
     * <code>1024</code>. For those values of <code>L</code>, this
     * implementation uses pre-computed values of <code>p</code>,
     * <code>q</code>, and <code>g</code> given in the document
     * <i>CryptoSpec</i> included in the security guide documentation of the
     * standard JDK distribution.
     * <p>
     * The DSS requires two primes , <code>p</code> and <code>q</code>,
     * satisfying the following three conditions:
     * <ul>
     * <li><code>2<sup>159</sup> &lt; q &lt; 2<sup>160</sup></code></li>
     * <li><code>2<sup>L-1</sup> &lt; p &lt; 2<sup>L</sup></code> for a
     * specified <code>L</code>, where <code>L = 512 + 64j</code> for some
     * <code>0 &lt;= j &lt;= 8</code></li>
     * <li>q divides p - 1.</li>
     * </ul>
     * The algorithm used to find these primes is as described in FIPS-186,
     * section 2.2: GENERATION OF PRIMES. This prime generation scheme starts by
     * using the {@link Sha160} and a user supplied <i>SEED</i> to construct a
     * prime, <code>q</code>, in the range 2<sup>159</sup> &lt; q &lt;
     * 2<sup>160</sup>. Once this is accomplished, the same <i>SEED</i> value is
     * used to construct an <code>X</code> in the range <code>2<sup>L-1
     * </sup> &lt; X &lt; 2<sup>L</sup>. The prime, <code>p</code>, is then
     * formed by rounding <code>X</code> to a number congruent to <code>1 mod
     * 2q</code>. In this implementation we use the same <i>SEED</i> value given
     * in FIPS-186, Appendix 5.
     */
    public BigInteger[] generateParameters()
    {
	int counter, offset;
	BigInteger SEED, alpha, U, q, OFFSET, SEED_PLUS_OFFSET, W, X, p, c, g;
	byte[] a, u;
	byte[] kb = new byte[20]; // to hold 160 bits of randomness

	// Let L-1 = n*160 + b, where b and n are integers and 0 <= b < 160.
	int b = (L - 1) % 160;
	int n = (L - 1 - b) / 160;
	BigInteger[] V = new BigInteger[n + 1];
	algorithm: while (true)
	{
	    step1: while (true)
	    {
		// 1. Choose an arbitrary sequence of at least 160 bits and
		// call it SEED.
		nextRandomBytes(kb);
		SEED = new BigInteger(1, kb).setBit(159).setBit(0);
		// Let g be the length of SEED in bits. here always 160
		// 2. Compute: U = SHA[SEED] XOR SHA[(SEED+1) mod 2**g]
		alpha = SEED.add(BigInteger.ONE).mod(TWO_POW_160);
		synchronized (sha)
		{
		    a = SEED.toByteArray();
		    sha.update(a, 0, a.length);
		    a = sha.digest();
		    u = alpha.toByteArray();
		    sha.update(u, 0, u.length);
		    u = sha.digest();
		}
		for (int i = 0; i < a.length; i++)
		    a[i] ^= u[i];

		U = new BigInteger(1, a);
		// 3. Form q from U by setting the most significant bit (the
		// 2**159 bit) and the least significant bit to 1. In terms of
		// boolean operations, q = U OR 2**159 OR 1. Note that
		// 2**159 < q < 2**160.
		q = U.setBit(159).setBit(0);
		// 4. Use a robust primality testing algorithm to test whether
		// q is prime(1). A robust primality test is one where the
		// probability of a non-prime number passing the test is at
		// most 1/2**80.
		// 5. If q is not prime, go to step 1.
		if (q.isProbablePrime(80))
		    break step1;
	    } // step1
	    // 6. Let counter = 0 and offset = 2.
	    counter = 0;
	    offset = 2;
	    while (true)
	    {
		OFFSET = BigInteger.valueOf(offset & 0xFFFFFFFFL);
		SEED_PLUS_OFFSET = SEED.add(OFFSET);
		// 7. For k = 0,...,n let V[k] = SHA[(SEED + offset + k) mod
		// 2**g].
		synchronized (sha)
		{
		    for (int k = 0; k <= n; k++)
		    {
			a = SEED_PLUS_OFFSET
				.add(BigInteger.valueOf(k & 0xFFFFFFFFL))
				.mod(TWO_POW_160).toByteArray();
			sha.update(a, 0, a.length);
			V[k] = new BigInteger(1, sha.digest());
		    }
		}
		// 8. Let W be the integer:
		// V[0]+V[1]*2**160+...+V[n-1]*2**((n-1)*160)+(V[n]mod2**b)*2**(n*160)
		// and let : X = W + 2**(L-1).
		// Note that 0 <= W < 2**(L-1) and hence 2**(L-1) <= X < 2**L.
		W = V[0];
		for (int k = 1; k < n; k++)
		    W = W.add(V[k].multiply(TWO.pow(k * 160)));

		W = W.add(V[n].mod(TWO.pow(b)).multiply(TWO.pow(n * 160)));
		X = W.add(TWO.pow(L - 1));
		// 9. Let c = X mod 2q and set p = X - (c - 1).
		// Note that p is congruent to 1 mod 2q.
		c = X.mod(TWO.multiply(q));
		p = X.subtract(c.subtract(BigInteger.ONE));
		// 10. If p < 2**(L-1), then go to step 13.
		if (p.compareTo(TWO.pow(L - 1)) >= 0)
		{
		    // 11. Perform a robust primality test on p.
		    // 12. If p passes the test performed in step 11, go to step
		    // 15.
		    if (p.isProbablePrime(80))
			break algorithm;
		}
		// 13. Let counter = counter + 1 and offset = offset + n + 1.
		counter++;
		offset += n + 1;
		// 14. If counter >= 4096 go to step 1, otherwise go to step 7.
		if (counter >= 4096)
		    continue algorithm;
	    } // step7
	} // algorithm
	// compute g. from FIPS-186, Appendix 4:
	// 1. Generate p and q as specified in Appendix 2.
	// 2. Let e = (p - 1) / q
	BigInteger e = p.subtract(BigInteger.ONE).divide(q);
	BigInteger h = TWO;
	BigInteger p_minus_1 = p.subtract(BigInteger.ONE);
	g = TWO;
	// 3. Set h = any integer, where 1 < h < p - 1 and
	// h differs from any value previously tried
	for (; h.compareTo(p_minus_1) < 0; h = h.add(BigInteger.ONE))
	{
	    // 4. Set g = h**e mod p
	    g = h.modPow(e, p);
	    // 5. If g = 1, go to step 3
	    if (!g.equals(BigInteger.ONE))
		break;
	}
	return new BigInteger[] { SEED, BigInteger.valueOf(counter), q, p, e,
		g };
    }

    private PRNG getDefaultPRNG()
    {
	if (prng == null)
	    prng = PRNG.getInstance();

	return prng;
    }

    /**
     * Fills the designated byte array with random data.
     *
     * @param buffer
     *            the byte array to fill with random data.
     */
    private void nextRandomBytes(byte[] buffer)
    {
	if (rnd != null)
	    rnd.nextBytes(buffer);
	else
	    getDefaultPRNG().nextBytes(buffer);
    }
}
