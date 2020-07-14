/* SecretKeyFactoryImpl.java -- simple byte array-wrapping factory.
   Copyright (C) 2004, 2006  Free Software Foundation, Inc.

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

package com.distrimind.gnu.jgnux.crypto.jce.key;

import com.distrimind.gnu.vm.jgnu.security.InvalidKeyException;
import com.distrimind.gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import com.distrimind.gnu.vm.jgnu.security.spec.KeySpec;
import com.distrimind.gnu.vm.jgnux.crypto.SecretKey;
import com.distrimind.gnu.vm.jgnux.crypto.SecretKeyFactorySpi;
import com.distrimind.gnu.vm.jgnux.crypto.spec.SecretKeySpec;

public abstract class SecretKeyFactoryImpl extends SecretKeyFactorySpi {

	protected SecretKeyFactoryImpl() {
	}

	@Override
	protected SecretKey engineGenerateSecret(KeySpec spec) throws InvalidKeySpecException {
		if (spec instanceof SecretKeySpec)
			return (SecretKey) spec;
		throw new InvalidKeySpecException("unknown key spec: " + spec.getClass().getName());
	}

	@Override
	protected KeySpec engineGetKeySpec(SecretKey key, Class<?> spec) throws InvalidKeySpecException {
		if (spec.equals(SecretKeySpec.class)) {
			if (key instanceof SecretKeySpec)
				return (KeySpec) key;
			else
				return new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
		}
		throw new InvalidKeySpecException("unsupported key spec: " + spec.getName());
	}

	@Override
	protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
		if (!"RAW".equals(key.getFormat()))
			throw new InvalidKeyException("only raw keys are supported");
		// SecretKeySpec is good enough for our purposes.
		return new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
	}
}