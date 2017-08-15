/* BaseKeyAgreementParty.java --
   Copyright (C) 2003, 2006 Free Software Foundation, Inc.

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

package gnu.jgnux.crypto.key;

import java.math.BigInteger;
import java.util.Map;

import gnu.jgnu.security.prng.IRandom;
import gnu.jgnu.security.prng.LimitReachedException;
import gnu.jgnu.security.util.PRNG;
import gnu.vm.jgnu.security.SecureRandom;

/**
 * A base abstract class to facilitate implementations of concrete key agreement
 * protocol handlers.
 */
public abstract class BaseKeyAgreementParty implements IKeyAgreementParty {
	protected static final BigInteger TWO = BigInteger.valueOf(2L);

	/** The canonical name of the protocol. */
	protected String name;

	/** Whether the instance is initialised or not. */
	protected boolean initialised = false;

	/** The current step index of the protocol exchange. */
	protected int step = -1;

	/** Whether the exchange has concluded or not. */
	protected boolean complete = false;

	/** The optional {@link SecureRandom} instance to use. */
	protected SecureRandom rnd = null;

	/** The optional {@link IRandom} instance to use. */
	protected IRandom irnd = null;

	/** Our default source of randomness. */
	private PRNG prng = null;

	protected BaseKeyAgreementParty(String name) {
		super();

		this.name = name;
	}

	protected abstract void engineInit(Map<String, Object> attributes) throws KeyAgreementException;

	protected abstract OutgoingMessage engineProcessMessage(IncomingMessage in) throws KeyAgreementException;

	protected abstract void engineReset();

	protected abstract byte[] engineSharedSecret() throws KeyAgreementException;

	private PRNG getDefaultPRNG() {
		if (prng == null)
			prng = PRNG.getInstance();

		return prng;
	}

	@Override
	public byte[] getSharedSecret() throws KeyAgreementException {
		if (!initialised)
			throw new KeyAgreementException("not yet initialised");
		if (!isComplete())
			throw new KeyAgreementException("not yet computed");
		return engineSharedSecret();
	}

	@Override
	public void init(Map<String, Object> attributes) throws KeyAgreementException {
		if (initialised)
			throw new IllegalStateException("already initialised");
		this.engineInit(attributes);
		initialised = true;
		this.step = -1;
		this.complete = false;
	}

	@Override
	public boolean isComplete() {
		return complete;
	}

	@Override
	public String name() {
		return name;
	}

	/**
	 * Fills the designated byte array with random data.
	 *
	 * @param buffer
	 *            the byte array to fill with random data.
	 */
	protected void nextRandomBytes(byte[] buffer) {
		if (rnd != null)
			rnd.nextBytes(buffer);
		else if (irnd != null)
			try {
				irnd.nextBytes(buffer, 0, buffer.length);
			} catch (LimitReachedException lre) {
				irnd = null;
				getDefaultPRNG().nextBytes(buffer);
			}
		else
			getDefaultPRNG().nextBytes(buffer);
	}

	@Override
	public OutgoingMessage processMessage(IncomingMessage in) throws KeyAgreementException {
		if (!initialised)
			throw new IllegalStateException("not initialised");
		if (complete)
			throw new IllegalStateException("exchange has already concluded");
		step++;
		return this.engineProcessMessage(in);
	}

	@Override
	public void reset() {
		if (initialised) {
			this.engineReset();
			initialised = false;
		}
	}
}
