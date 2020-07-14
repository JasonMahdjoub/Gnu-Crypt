/* GnuCrypto.java --
   Copyright (C) 2004, 2006 Free Software Foundation, Inc.

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

package com.distrimind.gnu.jgnux.crypto.jce;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Set;

import com.distrimind.gnu.jgnu.security.Registry;
import com.distrimind.gnu.jgnux.crypto.cipher.CipherFactory;
import com.distrimind.gnu.jgnux.crypto.mac.MacFactory;
import com.distrimind.gnu.vm.jgnu.security.Provider;

/**
 * The additional GNU algorithm implementation as a Java Cryptographic Extension
 * (JCE) Provider.
 *
 * @see java.security.Provider
 */
public final class GnuCrypto extends Provider {
	/**
	 * 
	 */
	private static final long serialVersionUID = -2353552339981756393L;

	/**
	 * Returns a {@link Set} of names of symmetric key block cipher algorithms
	 * available from this {@link Provider}.
	 *
	 * @return a {@link Set} of cipher names (Strings).
	 */
	public static final Set<String> getCipherNames() {
		HashSet<String> s = new HashSet<>();
		s.addAll(CipherFactory.getNames());
		s.add(Registry.ARCFOUR_PRNG);
		return s;
	}

	/**
	 * Returns a {@link Set} of names of MAC algorithms available from this
	 * {@link Provider}.
	 *
	 * @return a {@link Set} of MAC names (Strings).
	 */
	public static final Set<String> getMacNames() {
		return MacFactory.getNames();
	}

	public GnuCrypto() {
		super(Registry.GNU_CRYPTO, 2.1, "GNU Crypto JCE Provider");

		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			@Override
			public Object run() {
				// Cipher
				put("Cipher.ANUBIS", com.distrimind.gnu.jgnux.crypto.jce.cipher.AnubisSpi.class.getName());
				put("Cipher.ANUBIS ImplementedIn", "Software");
				put("Cipher.ARCFOUR", com.distrimind.gnu.jgnux.crypto.jce.cipher.ARCFourSpi.class.getName());
				put("Cipher.ARCFOUR ImplementedIn", "Software");
				put("Cipher.BLOWFISH", com.distrimind.gnu.jgnux.crypto.jce.cipher.BlowfishSpi.class.getName());
				put("Cipher.BLOWFISH ImplementedIn", "Software");
				put("Cipher.DES", com.distrimind.gnu.jgnux.crypto.jce.cipher.DESSpi.class.getName());
				put("Cipher.DES ImplementedIn", "Software");
				put("Cipher.KHAZAD", com.distrimind.gnu.jgnux.crypto.jce.cipher.KhazadSpi.class.getName());
				put("Cipher.KHAZAD ImplementedIn", "Software");
				put("Cipher.NULL", com.distrimind.gnu.jgnux.crypto.jce.cipher.NullCipherSpi.class.getName());
				put("Cipher.NULL ImplementedIn", "Software");
				put("Cipher.AES", com.distrimind.gnu.jgnux.crypto.jce.cipher.RijndaelSpi.class.getName());
				put("Cipher.AES ImplementedIn", "Software");
				put("Cipher.RIJNDAEL", com.distrimind.gnu.jgnux.crypto.jce.cipher.RijndaelSpi.class.getName());
				put("Cipher.RIJNDAEL ImplementedIn", "Software");
				put("Cipher.SERPENT", com.distrimind.gnu.jgnux.crypto.jce.cipher.SerpentSpi.class.getName());
				put("Cipher.SERPENT ImplementedIn", "Software");
				put("Cipher.SQUARE", com.distrimind.gnu.jgnux.crypto.jce.cipher.SquareSpi.class.getName());
				put("Cipher.SQUARE ImplementedIn", "Software");
				put("Cipher.TRIPLEDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.TripleDESSpi.class.getName());
				put("Cipher.TRIPLEDES ImplementedIn", "Software");
				put("Cipher.TWOFISH", com.distrimind.gnu.jgnux.crypto.jce.cipher.TwofishSpi.class.getName());
				put("Cipher.TWOFISH ImplementedIn", "Software");
				put("Cipher.CAST5", com.distrimind.gnu.jgnux.crypto.jce.cipher.Cast5Spi.class.getName());
				put("Cipher.CAST5 ImplementedIn", "Software");

				// PBES2 ciphers.
				put("Cipher.PBEWithHMacHavalAndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.AES.class.getName());
				put("Cipher.PBEWithHMacHavalAndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Anubis.class.getName());
				put("Cipher.PBEWithHMacHavalAndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Blowfish.class.getName());
				put("Cipher.PBEWithHMacHavalAndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Cast5.class.getName());
				put("Cipher.PBEWithHMacHavalAndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.DES.class.getName());
				put("Cipher.PBEWithHMacHavalAndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Khazad.class.getName());
				put("Cipher.PBEWithHMacHavalAndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Serpent.class.getName());
				put("Cipher.PBEWithHMacHavalAndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Square.class.getName());
				put("Cipher.PBEWithHMacHavalAndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.TripleDES.class.getName());
				put("Cipher.PBEWithHMacHavalAndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacHaval.Twofish.class.getName());

				put("Cipher.PBEWithHMacMD2AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.AES.class.getName());
				put("Cipher.PBEWithHMacMD2AndAnubis", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Anubis.class.getName());
				put("Cipher.PBEWithHMacMD2AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Blowfish.class.getName());
				put("Cipher.PBEWithHMacMD2AndCast5", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Cast5.class.getName());
				put("Cipher.PBEWithHMacMD2AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.DES.class.getName());
				put("Cipher.PBEWithHMacMD2AndKhazad", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Khazad.class.getName());
				put("Cipher.PBEWithHMacMD2AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Serpent.class.getName());
				put("Cipher.PBEWithHMacMD2AndSquare", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Square.class.getName());
				put("Cipher.PBEWithHMacMD2AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.TripleDES.class.getName());
				put("Cipher.PBEWithHMacMD2AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD2.Twofish.class.getName());

				put("Cipher.PBEWithHMacMD4AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.AES.class.getName());
				put("Cipher.PBEWithHMacMD4AndAnubis", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Anubis.class.getName());
				put("Cipher.PBEWithHMacMD4AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Blowfish.class.getName());
				put("Cipher.PBEWithHMacMD4AndCast5", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Cast5.class.getName());
				put("Cipher.PBEWithHMacMD4AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.DES.class.getName());
				put("Cipher.PBEWithHMacMD4AndKhazad", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Khazad.class.getName());
				put("Cipher.PBEWithHMacMD4AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Serpent.class.getName());
				put("Cipher.PBEWithHMacMD4AndSquare", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Square.class.getName());
				put("Cipher.PBEWithHMacMD4AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.TripleDES.class.getName());
				put("Cipher.PBEWithHMacMD4AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD4.Twofish.class.getName());

				put("Cipher.PBEWithHMacMD5AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.AES.class.getName());
				put("Cipher.PBEWithHMacMD5AndAnubis", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Anubis.class.getName());
				put("Cipher.PBEWithHMacMD5AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Blowfish.class.getName());
				put("Cipher.PBEWithHMacMD5AndCast5", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Cast5.class.getName());
				put("Cipher.PBEWithHMacMD5AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.DES.class.getName());
				put("Cipher.PBEWithHMacMD5AndKhazad", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Khazad.class.getName());
				put("Cipher.PBEWithHMacMD5AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Serpent.class.getName());
				put("Cipher.PBEWithHMacMD5AndSquare", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Square.class.getName());
				put("Cipher.PBEWithHMacMD5AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.TripleDES.class.getName());
				put("Cipher.PBEWithHMacMD5AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacMD5.Twofish.class.getName());

				put("Cipher.PBEWithHMacSHA1AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.AES.class.getName());
				put("Cipher.PBEWithHMacSHA1AndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Anubis.class.getName());
				put("Cipher.PBEWithHMacSHA1AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Blowfish.class.getName());
				put("Cipher.PBEWithHMacSHA1AndCast5", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Cast5.class.getName());
				put("Cipher.PBEWithHMacSHA1AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.DES.class.getName());
				put("Cipher.PBEWithHMacSHA1AndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Khazad.class.getName());
				put("Cipher.PBEWithHMacSHA1AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Serpent.class.getName());
				put("Cipher.PBEWithHMacSHA1AndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Square.class.getName());
				put("Cipher.PBEWithHMacSHA1AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.TripleDES.class.getName());
				put("Cipher.PBEWithHMacSHA1AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA1.Twofish.class.getName());

				put("Cipher.PBEWithHMacSHA256AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.AES.class.getName());
				put("Cipher.PBEWithHMacSHA256AndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Anubis.class.getName());
				put("Cipher.PBEWithHMacSHA256AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Blowfish.class.getName());
				put("Cipher.PBEWithHMacSHA256AndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Cast5.class.getName());
				put("Cipher.PBEWithHMacSHA256AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.DES.class.getName());
				put("Cipher.PBEWithHMacSHA256AndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Khazad.class.getName());
				put("Cipher.PBEWithHMacSHA256AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Serpent.class.getName());
				put("Cipher.PBEWithHMacSHA256AndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Square.class.getName());
				put("Cipher.PBEWithHMacSHA256AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.TripleDES.class.getName());
				put("Cipher.PBEWithHMacSHA256AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA256.Twofish.class.getName());

				put("Cipher.PBEWithHMacSHA384AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.AES.class.getName());
				put("Cipher.PBEWithHMacSHA384AndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Anubis.class.getName());
				put("Cipher.PBEWithHMacSHA384AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Blowfish.class.getName());
				put("Cipher.PBEWithHMacSHA384AndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Cast5.class.getName());
				put("Cipher.PBEWithHMacSHA384AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.DES.class.getName());
				put("Cipher.PBEWithHMacSHA384AndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Khazad.class.getName());
				put("Cipher.PBEWithHMacSHA384AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Serpent.class.getName());
				put("Cipher.PBEWithHMacSHA384AndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Square.class.getName());
				put("Cipher.PBEWithHMacSHA384AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.TripleDES.class.getName());
				put("Cipher.PBEWithHMacSHA384AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA384.Twofish.class.getName());

				put("Cipher.PBEWithHMacSHA512AndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.AES.class.getName());
				put("Cipher.PBEWithHMacSHA512AndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Anubis.class.getName());
				put("Cipher.PBEWithHMacSHA512AndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Blowfish.class.getName());
				put("Cipher.PBEWithHMacSHA512AndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Cast5.class.getName());
				put("Cipher.PBEWithHMacSHA512AndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.DES.class.getName());
				put("Cipher.PBEWithHMacSHA512AndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Khazad.class.getName());
				put("Cipher.PBEWithHMacSHA512AndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Serpent.class.getName());
				put("Cipher.PBEWithHMacSHA512AndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Square.class.getName());
				put("Cipher.PBEWithHMacSHA512AndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.TripleDES.class.getName());
				put("Cipher.PBEWithHMacSHA512AndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacSHA512.Twofish.class.getName());

				put("Cipher.PBEWithHMacTigerAndAES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.AES.class.getName());
				put("Cipher.PBEWithHMacTigerAndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Anubis.class.getName());
				put("Cipher.PBEWithHMacTigerAndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Blowfish.class.getName());
				put("Cipher.PBEWithHMacTigerAndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Cast5.class.getName());
				put("Cipher.PBEWithHMacTigerAndDES", com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.DES.class.getName());
				put("Cipher.PBEWithHMacTigerAndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Khazad.class.getName());
				put("Cipher.PBEWithHMacTigerAndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Serpent.class.getName());
				put("Cipher.PBEWithHMacTigerAndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Square.class.getName());
				put("Cipher.PBEWithHMacTigerAndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.TripleDES.class.getName());
				put("Cipher.PBEWithHMacTigerAndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacTiger.Twofish.class.getName());

				put("Cipher.PBEWithHMacWhirlpoolAndAES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.AES.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndAnubis",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Anubis.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndBlowfish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Blowfish.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndCast5",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Cast5.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.DES.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndKhazad",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Khazad.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndSerpent",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Serpent.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndSquare",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Square.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndTripleDES",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.TripleDES.class.getName());
				put("Cipher.PBEWithHMacWhirlpoolAndTwofish",
						com.distrimind.gnu.jgnux.crypto.jce.cipher.PBES2.HMacWhirlpool.Twofish.class.getName());

				// Key Wrapping Algorithm cipher
				put("Cipher." + Registry.AES128_KWA, com.distrimind.gnu.jgnux.crypto.jce.cipher.AES128KeyWrapSpi.class.getName());
				put("Cipher." + Registry.AES192_KWA, com.distrimind.gnu.jgnux.crypto.jce.cipher.AES192KeyWrapSpi.class.getName());
				put("Cipher." + Registry.AES256_KWA, com.distrimind.gnu.jgnux.crypto.jce.cipher.AES256KeyWrapSpi.class.getName());
				put("Cipher." + Registry.TRIPLEDES_KWA,
						com.distrimind.gnu.jgnux.crypto.jce.cipher.TripleDESKeyWrapSpi.class.getName());

				// SecretKeyFactory interface to PBKDF2.
				put("SecretKeyFactory.PBKDF2WithHMacHaval",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacHaval.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacMD2",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacMD2.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacMD4",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacMD4.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacMD5",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacMD5.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacSHA1",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacSHA1.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacSHA256",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacSHA256.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacSHA384",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacSHA384.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacSHA512",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacSHA512.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacTiger",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacTiger.class.getName());
				put("SecretKeyFactory.PBKDF2WithHMacWhirlpool",
						com.distrimind.gnu.jgnux.crypto.jce.PBKDF2SecretKeyFactory.HMacWhirlpool.class.getName());

				// Simple SecretKeyFactory implementations.
				put("SecretKeyFactory.Anubis", com.distrimind.gnu.jgnux.crypto.jce.key.AnubisSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Blowfish", com.distrimind.gnu.jgnux.crypto.jce.key.BlowfishSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Cast5", com.distrimind.gnu.jgnux.crypto.jce.key.Cast5SecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.DES", com.distrimind.gnu.jgnux.crypto.jce.key.DESSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Khazad", com.distrimind.gnu.jgnux.crypto.jce.key.KhazadSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Rijndael", com.distrimind.gnu.jgnux.crypto.jce.key.RijndaelSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Serpent", com.distrimind.gnu.jgnux.crypto.jce.key.SerpentSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.Square", com.distrimind.gnu.jgnux.crypto.jce.key.SquareSecretKeyFactoryImpl.class.getName());
				put("SecretKeyFactory.TripleDES", com.distrimind.gnu.jgnux.crypto.jce.key.DESedeSecretKeyFactoryImpl.class.getName());
				put("Alg.Alias.SecretKeyFactory.AES", "Rijndael");
				put("Alg.Alias.SecretKeyFactory.DESede", "TripleDES");
				put("Alg.Alias.SecretKeyFactory.3-DES", "TripleDES");
				put("Alg.Alias.SecretKeyFactory.3DES", "TripleDES");

				put("AlgorithmParameters.BlockCipherParameters",
						com.distrimind.gnu.jgnux.crypto.jce.params.BlockCipherParameters.class.getName());
				put("Alg.Alias.AlgorithmParameters.Anubis", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Blowfish", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Cast5", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.DES", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Khazad", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Rijndael", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.AES", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Serpent", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.Square", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.TripleDES", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.DESede", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.3-DES", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.3DES", "BlockCipherParameters");

				// KeyGenerator Adapter implementations
				put("KeyGenerator.Anubis", com.distrimind.gnu.jgnux.crypto.jce.key.AnubisKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Blowfish", com.distrimind.gnu.jgnux.crypto.jce.key.BlowfishKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Cast5", com.distrimind.gnu.jgnux.crypto.jce.key.Cast5KeyGeneratorImpl.class.getName());
				put("KeyGenerator.DES", com.distrimind.gnu.jgnux.crypto.jce.key.DESKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Khazad", com.distrimind.gnu.jgnux.crypto.jce.key.KhazadKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Rijndael", com.distrimind.gnu.jgnux.crypto.jce.key.RijndaelKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Serpent", com.distrimind.gnu.jgnux.crypto.jce.key.SerpentKeyGeneratorImpl.class.getName());
				put("KeyGenerator.Square", com.distrimind.gnu.jgnux.crypto.jce.key.SquareKeyGeneratorImpl.class.getName());
				put("KeyGenerator.TripleDES", com.distrimind.gnu.jgnux.crypto.jce.key.TripleDESKeyGeneratorImpl.class.getName());
				put("KeyGenerator.TwoFish", com.distrimind.gnu.jgnux.crypto.jce.key.TwofishKeyGeneratorImpl.class.getName());
				put("Alg.Alias.KeyGenerator.AES", "Rijndael");
				put("Alg.Alias.KeyGenerator.DESede", "TripleDES");
				put("Alg.Alias.KeyGenerator.3-DES", "TripleDES");
				put("Alg.Alias.KeyGenerator.3DES", "TripleDES");

				// MAC
				put("Mac.HMAC-MD2", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacMD2Spi.class.getName());
				put("Mac.HMAC-MD4", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacMD4Spi.class.getName());
				put("Mac.HMAC-MD5", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacMD5Spi.class.getName());
				put("Mac.HMAC-RIPEMD128", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacRipeMD128Spi.class.getName());
				put("Mac.HMAC-RIPEMD160", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacRipeMD160Spi.class.getName());
				put("Mac.HMAC-SHA160", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacSHA160Spi.class.getName());
				put("Mac.HMAC-SHA256", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacSHA256Spi.class.getName());
				put("Mac.HMAC-SHA384", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacSHA384Spi.class.getName());
				put("Mac.HMAC-SHA512", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacSHA512Spi.class.getName());
				put("Mac.HMAC-TIGER", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacTigerSpi.class.getName());
				put("Mac.HMAC-HAVAL", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacHavalSpi.class.getName());
				put("Mac.HMAC-WHIRLPOOL", com.distrimind.gnu.jgnux.crypto.jce.mac.HMacWhirlpoolSpi.class.getName());
				put("Mac.TMMH16", com.distrimind.gnu.jgnux.crypto.jce.mac.TMMH16Spi.class.getName());
				put("Mac.UHASH32", com.distrimind.gnu.jgnux.crypto.jce.mac.UHash32Spi.class.getName());
				put("Mac.UMAC32", com.distrimind.gnu.jgnux.crypto.jce.mac.UMac32Spi.class.getName());

				put("Mac.OMAC-ANUBIS", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacAnubisImpl.class.getName());
				put("Mac.OMAC-BLOWFISH", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacBlowfishImpl.class.getName());
				put("Mac.OMAC-CAST5", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacCast5Impl.class.getName());
				put("Mac.OMAC-DES", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacDESImpl.class.getName());
				put("Mac.OMAC-KHAZAD", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacKhazadImpl.class.getName());
				put("Mac.OMAC-RIJNDAEL", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacRijndaelImpl.class.getName());
				put("Mac.OMAC-SERPENT", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacSerpentImpl.class.getName());
				put("Mac.OMAC-SQUARE", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacSquareImpl.class.getName());
				put("Mac.OMAC-TRIPLEDES", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacTripleDESImpl.class.getName());
				put("Mac.OMAC-TWOFISH", com.distrimind.gnu.jgnux.crypto.jce.mac.OMacTwofishImpl.class.getName());

				// Aliases
				put("Alg.Alias.AlgorithmParameters.AES", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.BLOWFISH", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.ANUBIS", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.KHAZAD", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.NULL", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.RIJNDAEL", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.SERPENT", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.SQUARE", "BlockCipherParameters");
				put("Alg.Alias.AlgorithmParameters.TWOFISH", "BlockCipherParameters");
				put("Alg.Alias.Cipher.RC4", "ARCFOUR");
				put("Alg.Alias.Cipher.3-DES", "TRIPLEDES");
				put("Alg.Alias.Cipher.3DES", "TRIPLEDES");
				put("Alg.Alias.Cipher.DES-EDE", "TRIPLEDES");
				put("Alg.Alias.Cipher.DESede", "TRIPLEDES");
				put("Alg.Alias.Cipher.CAST128", "CAST5");
				put("Alg.Alias.Cipher.CAST-128", "CAST5");
				put("Alg.Alias.Mac.HMAC-SHS", "HMAC-SHA160");
				put("Alg.Alias.Mac.HMAC-SHA", "HMAC-SHA160");
				put("Alg.Alias.Mac.HMAC-SHA1", "HMAC-SHA160");
				put("Alg.Alias.Mac.HMAC-SHA-160", "HMAC-SHA160");
				put("Alg.Alias.Mac.HMAC-SHA-256", "HMAC-SHA256");
				put("Alg.Alias.Mac.HMAC-SHA-384", "HMAC-SHA384");
				put("Alg.Alias.Mac.HMAC-SHA-512", "HMAC-SHA512");
				put("Alg.Alias.Mac.HMAC-RIPEMD-160", "HMAC-RIPEMD160");
				put("Alg.Alias.Mac.HMAC-RIPEMD-128", "HMAC-RIPEMD128");
				put("Alg.Alias.Mac.OMAC-AES", "OMAC-RIJNDAEL");
				put("Alg.Alias.Mac.OMAC-3DES", "OMAC-3DES");
				put("Alg.Alias.Mac.HmacMD4", "HMAC-MD4");
				put("Alg.Alias.Mac.HmacMD5", "HMAC-MD5");
				put("Alg.Alias.Mac.HmacSHA-1", "HMAC-SHA-1");
				put("Alg.Alias.Mac.HmacSHA1", "HMAC-SHA1");
				put("Alg.Alias.Mac.HmacSHA-160", "HMAC-SHA-160");
				put("Alg.Alias.Mac.HmacSHA160", "HMAC-SHA-160");
				put("Alg.Alias.Mac.HmacSHA-256", "HMAC-SHA-256");
				put("Alg.Alias.Mac.HmacSHA256", "HMAC-SHA-256");
				put("Alg.Alias.Mac.HmacSHA-384", "HMAC-SHA-384");
				put("Alg.Alias.Mac.HmacSHA384", "HMAC-SHA-384");
				put("Alg.Alias.Mac.HmacSHA-512", "HMAC-SHA-512");
				put("Alg.Alias.Mac.HmacSHA512", "HMAC-SHA-512");
				put("Alg.Alias.Mac.HmacRIPEMD128", "HMAC-RIPEMD128");
				put("Alg.Alias.Mac.HmacRIPEMD-128", "HMAC-RIPEMD128");
				put("Alg.Alias.Mac.HmacRIPEMD160", "HMAC-RIPEMD160");
				put("Alg.Alias.Mac.HmacRIPEMD-160", "HMAC-RIPEMD160");
				put("Alg.Alias.Mac.HmacTiger", "HMAC-TIGER");
				put("Alg.Alias.Mac.HmacHaval", "HMAC-HAVAL");
				put("Alg.Alias.Mac.HmacWhirlpool", "HMAC-WHIRLPOOL");

				// KeyAgreement
				put("KeyAgreement.DH", com.distrimind.gnu.jgnux.crypto.jce.DiffieHellmanImpl.class.getName());
				put("Alg.Alias.KeyAgreement.DiffieHellman", "DH");

				// Cipher
				put("Cipher.RSAES-PKCS1-v1_5", com.distrimind.gnu.jgnux.crypto.RSACipherImpl.class.getName());
				put("Alg.Alias.Cipher.RSA", "RSAES-PKCS1-v1_5");

				// SecureRandom
				put("SecureRandom.ARCFOUR", com.distrimind.gnu.jgnux.crypto.jce.prng.ARCFourRandomSpi.class.getName());
				put("SecureRandom.ARCFOUR ImplementedIn", "Software");
				put("SecureRandom.CSPRNG", com.distrimind.gnu.jgnux.crypto.jce.prng.CSPRNGSpi.class.getName());
				put("SecureRandom.CSPRNG ImplementedIn", "Software");
				put("SecureRandom.ICM", com.distrimind.gnu.jgnux.crypto.jce.prng.ICMRandomSpi.class.getName());
				put("SecureRandom.ICM ImplementedIn", "Software");
				put("SecureRandom.UMAC-KDF", com.distrimind.gnu.jgnux.crypto.jce.prng.UMacRandomSpi.class.getName());
				put("SecureRandom.UMAC-KDF ImplementedIn", "Software");
				put("SecureRandom.Fortuna", com.distrimind.gnu.jgnux.crypto.jce.prng.FortunaImpl.class.getName());
				put("SecureRandom.Fortuna ImplementedIn", "Software");

				// KeyStore
				put("KeyStore.GKR", com.distrimind.gnu.jgnux.crypto.jce.keyring.GnuKeyring.class.getName());
				put("Alg.Alias.KeyStore.GnuKeyring", "GKR");

				// KeyPairGenerator
				// ---------------------------------------------------
				put("KeyPairGenerator.DH", com.distrimind.gnu.jgnux.crypto.jce.sig.DHKeyPairGeneratorSpi.class.getName());
				put("KeyPairGenerator.DH KeySize", "512");
				put("KeyPairGenerator.DH ImplementedIn", "Software");

				put("Alg.Alias.KeyPairGenerator.DiffieHellman", "DH");

				// KeyFactory
				// ---------------------------------------------------------
				put("KeyFactory.DH", com.distrimind.gnu.jgnux.crypto.jce.sig.DHKeyFactory.class.getName());

				put("Alg.Alias,KeyFactory.DiffieHellman", "DH");

				// Algorithm Parameters
				// -----------------------------------------------
				put("AlgorithmParameters.DH", com.distrimind.gnu.jgnux.crypto.jce.sig.DHParameters.class.getName());

				put("Alg.Alias.AlgorithmParameters.DiffieHellman", "DH");

				// Algorithm Parameters Generator
				// -------------------------------------
				put("AlgorithmParameterGenerator.DH", com.distrimind.gnu.jgnux.crypto.jce.sig.DHParametersGenerator.class.getName());

				put("Alg.Alias.AlgorithmParameterGenerator.DiffieHellman", "DH");

				return null;
			}
		});
	}
}
