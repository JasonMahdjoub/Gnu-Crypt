/* SRPServer.java --
   Copyright (C) 2003, 2006, 2010 Free Software Foundation, Inc.

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

package gnu.jgnux.crypto.sasl.srp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.StringTokenizer;

import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import gnu.jgnu.security.Registry;
import gnu.jgnu.security.util.PRNG;
import gnu.jgnux.crypto.assembly.Direction;
import gnu.jgnux.crypto.cipher.CipherFactory;
import gnu.jgnux.crypto.cipher.IBlockCipher;
import gnu.jgnux.crypto.key.IKeyAgreementParty;
import gnu.jgnux.crypto.key.IncomingMessage;
import gnu.jgnux.crypto.key.KeyAgreementException;
import gnu.jgnux.crypto.key.KeyAgreementFactory;
import gnu.jgnux.crypto.key.OutgoingMessage;
import gnu.jgnux.crypto.key.srp6.SRP6KeyAgreement;
import gnu.jgnux.crypto.sasl.IllegalMechanismStateException;
import gnu.jgnux.crypto.sasl.InputBuffer;
import gnu.jgnux.crypto.sasl.IntegrityException;
import gnu.jgnux.crypto.sasl.OutputBuffer;
import gnu.jgnux.crypto.sasl.ServerMechanism;

/**
 * The SASL-SRP server-side mechanism.
 */
public class SRPServer extends ServerMechanism implements SaslServer {
	private String U = null; // client's username

	private BigInteger N, g, A, B;

	private byte[] s; // salt

	private byte[] cIV, sIV; // client+server IVs, when confidentiality is on

	private byte[] cn, sn; // client's and server's nonce

	private SRP srp; // SRP algorithm instance used by this server

	private byte[] sid; // session ID when re-used

	private int ttl = 360; // session time-to-live in seconds

	private byte[] cCB; // peer's channel binding'

	private String mandatory; // List of available options

	private String L = null;

	private String o;

	private String chosenIntegrityAlgorithm;

	private String chosenConfidentialityAlgorithm;

	private int rawSendSize = Registry.SASL_BUFFER_MAX_LIMIT;

	private byte[] K; // shared session key

	private boolean replayDetection = true; // whether Replay Detection is on

	private int inCounter = 0; // messages sequence numbers

	private int outCounter = 0;

	private IALG inMac, outMac; // if !null, use for integrity

	private CALG inCipher, outCipher; // if !null, use for confidentiality

	private IKeyAgreementParty serverHandler = KeyAgreementFactory.getPartyBInstance(Registry.SRP_SASL_KA);

	/** Our default source of randomness. */
	private PRNG prng = null;

	public SRPServer() {
		super(Registry.SASL_SRP_MECHANISM);
	}

	private String createL() {
		String s = (String) properties.get(SRPRegistry.SRP_MANDATORY);
		if (s == null)
			s = SRPRegistry.DEFAULT_MANDATORY;

		if (!SRPRegistry.MANDATORY_NONE.equals(s) && !SRPRegistry.OPTION_REPLAY_DETECTION.equals(s)
				&& !SRPRegistry.OPTION_INTEGRITY.equals(s) && !SRPRegistry.OPTION_CONFIDENTIALITY.equals(s)) {
			s = SRPRegistry.DEFAULT_MANDATORY;
		}
		mandatory = s;
		s = (String) properties.get(SRPRegistry.SRP_CONFIDENTIALITY);
		final boolean confidentiality = (s == null ? SRPRegistry.DEFAULT_CONFIDENTIALITY
				: Boolean.valueOf(s).booleanValue());
		s = (String) properties.get(SRPRegistry.SRP_INTEGRITY_PROTECTION);
		boolean integrity = (s == null ? SRPRegistry.DEFAULT_INTEGRITY : Boolean.valueOf(s).booleanValue());
		s = (String) properties.get(SRPRegistry.SRP_REPLAY_DETECTION);
		final boolean replayDetection = (s == null ? SRPRegistry.DEFAULT_REPLAY_DETECTION
				: Boolean.valueOf(s).booleanValue());
		final StringBuilder sb = new StringBuilder();
		sb.append(SRPRegistry.OPTION_SRP_DIGEST).append("=").append(srp.getAlgorithm()).append(",");

		if (!SRPRegistry.MANDATORY_NONE.equals(mandatory))
			sb.append(SRPRegistry.OPTION_MANDATORY).append("=").append(mandatory).append(",");

		if (replayDetection) {
			sb.append(SRPRegistry.OPTION_REPLAY_DETECTION).append(",");
			// if replay detection is on then force integrity protection
			integrity = true;
		}
		int i;
		if (integrity) {
			for (i = 0; i < SRPRegistry.INTEGRITY_ALGORITHMS.length; i++)
				sb.append(SRPRegistry.OPTION_INTEGRITY).append("=").append(SRPRegistry.INTEGRITY_ALGORITHMS[i])
						.append(",");
		}
		if (confidentiality) {
			IBlockCipher cipher;
			for (i = 0; i < SRPRegistry.CONFIDENTIALITY_ALGORITHMS.length; i++) {
				cipher = CipherFactory.getInstance(SRPRegistry.CONFIDENTIALITY_ALGORITHMS[i]);
				if (cipher != null)
					sb.append(SRPRegistry.OPTION_CONFIDENTIALITY).append("=")
							.append(SRPRegistry.CONFIDENTIALITY_ALGORITHMS[i]).append(",");
			}
		}
		final String result = sb.append(SRPRegistry.OPTION_MAX_BUFFER_SIZE).append("=")
				.append(Registry.SASL_BUFFER_MAX_LIMIT).toString();
		return result;
	}

	@Override
	protected byte[] engineUnwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
		if (inMac == null && inCipher == null)
			throw new IllegalStateException("connection is not protected");
		// at this point one, or both, of confidentiality and integrity
		// protection
		// services are active.
		final byte[] result;
		try {
			if (inMac != null) { // integrity bytes are at the end of the stream
				final int macBytesCount = inMac.length();
				final int payloadLength = len - macBytesCount;
				final byte[] received_mac = new byte[macBytesCount];
				System.arraycopy(incoming, offset + payloadLength, received_mac, 0, macBytesCount);
				inMac.update(incoming, offset, payloadLength);
				if (replayDetection) {
					inCounter++;
					inMac.update(new byte[] { (byte) (inCounter >>> 24), (byte) (inCounter >>> 16),
							(byte) (inCounter >>> 8), (byte) inCounter });
				}
				final byte[] computed_mac = inMac.doFinal();
				if (!Arrays.equals(received_mac, computed_mac))
					throw new IntegrityException("engineUnwrap()");
				// deal with the payload, which can be either plain or encrypted
				if (inCipher != null)
					result = inCipher.doFinal(incoming, offset, payloadLength);
				else {
					result = new byte[payloadLength];
					System.arraycopy(incoming, offset, result, 0, result.length);
				}
			} else // no integrity protection; just confidentiality
				result = inCipher.doFinal(incoming, offset, len);
		} catch (IOException x) {
			if (x instanceof SaslException)
				throw (SaslException) x;
			throw new SaslException("engineUnwrap()", x);
		}
		return result;
	}

	@Override
	protected byte[] engineWrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
		if (outMac == null && outCipher == null)
			throw new IllegalStateException("connection is not protected");
		// at this point one, or both, of confidentiality and integrity
		// protection
		// services are active.
		byte[] result;
		try {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			if (outCipher != null) {
				result = outCipher.doFinal(outgoing, offset, len);
				out.write(result);
				if (outMac != null) {
					outMac.update(result);
					if (replayDetection) {
						outCounter++;
						outMac.update(new byte[] { (byte) (outCounter >>> 24), (byte) (outCounter >>> 16),
								(byte) (outCounter >>> 8), (byte) outCounter });
					}
					final byte[] C = outMac.doFinal();
					out.write(C);
				}
				// else ciphertext only; do nothing
			} else // no confidentiality; just integrity [+ replay detection]
			{
				out.write(outgoing, offset, len);
				outMac.update(outgoing, offset, len);
				if (replayDetection) {
					outCounter++;
					outMac.update(new byte[] { (byte) (outCounter >>> 24), (byte) (outCounter >>> 16),
							(byte) (outCounter >>> 8), (byte) outCounter });
				}
				final byte[] C = outMac.doFinal();
				out.write(C);
			}
			result = out.toByteArray();
		} catch (IOException x) {
			if (x instanceof SaslException)
				throw (SaslException) x;
			throw new SaslException("engineWrap()", x);
		}
		return result;
	}

	@Override
	@SuppressWarnings("fallthrough")
	public byte[] evaluateResponse(final byte[] response) throws SaslException {
		switch (state) {
		case 0:
			if (response == null)
				return null;
			state++;
			return sendProtocolElements(response);
		case 1:
			if (!complete) {
				state++;
				return sendEvidence(response);
			}
			// else fall through
		default:
			throw new IllegalMechanismStateException("evaluateResponse()");
		}
	}

	private PRNG getDefaultPRNG() {
		if (prng == null)
			prng = PRNG.getInstance();
		return prng;
	}

	@Override
	protected String getNegotiatedQOP() {
		if (inMac != null) {
			if (inCipher != null)
				return Registry.QOP_AUTH_CONF;
			return Registry.QOP_AUTH_INT;
		}
		return Registry.QOP_AUTH;
	}

	@Override
	protected String getNegotiatedRawSendSize() {
		return String.valueOf(rawSendSize);
	}

	@Override
	protected String getNegotiatedStrength() {
		if (inMac != null) {
			if (inCipher != null)
				return Registry.STRENGTH_HIGH;
			return Registry.STRENGTH_MEDIUM;
		}
		return Registry.STRENGTH_LOW;
	}

	@Override
	protected String getReuse() {
		return Registry.REUSE_TRUE;
	}

	@Override
	@SuppressWarnings("unused")
	protected void initMechanism() throws SaslException {
		// TODO:
		// we must have a means to map a given username to a preferred
		// SRP hash algorithm; otherwise we end up using _always_ SHA.
		// for the time being get it from the mechanism properties map
		// and apply it for all users.
		final String mda = (String) properties.get(SRPRegistry.SRP_HASH);
		srp = SRP.instance(mda == null ? SRPRegistry.SRP_DEFAULT_DIGEST_NAME : mda);
	}

	// Parse client's options and set security layer variables
	private void parseO(final String o) throws AuthenticationException {
		this.replayDetection = false;
		boolean integrity = false;
		boolean confidentiality = false;
		String option;
		int i;

		final StringTokenizer st = new StringTokenizer(o.toLowerCase(), ",");
		while (st.hasMoreTokens()) {
			option = st.nextToken();
			if (option.equals(SRPRegistry.OPTION_REPLAY_DETECTION))
				replayDetection = true;
			else if (option.startsWith(SRPRegistry.OPTION_INTEGRITY + "=")) {
				if (integrity)
					throw new AuthenticationException("Only one integrity algorithm may be chosen");
				option = option.substring(option.indexOf('=') + 1);
				for (i = 0; i < SRPRegistry.INTEGRITY_ALGORITHMS.length; i++) {
					if (SRPRegistry.INTEGRITY_ALGORITHMS[i].equals(option)) {
						chosenIntegrityAlgorithm = option;
						integrity = true;
						break;
					}
				}
				if (!integrity)
					throw new AuthenticationException("Unknown integrity algorithm: " + option);
			} else if (option.startsWith(SRPRegistry.OPTION_CONFIDENTIALITY + "=")) {
				if (confidentiality)
					throw new AuthenticationException("Only one confidentiality algorithm may be chosen");
				option = option.substring(option.indexOf('=') + 1);
				for (i = 0; i < SRPRegistry.CONFIDENTIALITY_ALGORITHMS.length; i++) {
					if (SRPRegistry.CONFIDENTIALITY_ALGORITHMS[i].equals(option)) {
						chosenConfidentialityAlgorithm = option;
						confidentiality = true;
						break;
					}
				}
				if (!confidentiality)
					throw new AuthenticationException("Unknown confidentiality algorithm: " + option);
			} else if (option.startsWith(SRPRegistry.OPTION_MAX_BUFFER_SIZE + "=")) {
				final String maxBufferSize = option.substring(option.indexOf('=') + 1);
				try {
					rawSendSize = Integer.parseInt(maxBufferSize);
					if (rawSendSize > Registry.SASL_BUFFER_MAX_LIMIT || rawSendSize < 1)
						throw new AuthenticationException("Illegal value for 'maxbuffersize' option");
				} catch (NumberFormatException x) {
					throw new AuthenticationException(SRPRegistry.OPTION_MAX_BUFFER_SIZE + "=" + maxBufferSize, x);
				}
			}
		}
		// check if client did the right thing
		if (replayDetection) {
			if (!integrity)
				throw new AuthenticationException(
						"Missing integrity protection algorithm but replay detection is chosen");
		}
		if (mandatory.equals(SRPRegistry.OPTION_REPLAY_DETECTION)) {
			if (!replayDetection)
				throw new AuthenticationException("Replay detection is mandatory but was not chosen");
		}
		if (mandatory.equals(SRPRegistry.OPTION_INTEGRITY)) {
			if (!integrity)
				throw new AuthenticationException("Integrity protection is mandatory but was not chosen");
		}
		if (mandatory.equals(SRPRegistry.OPTION_CONFIDENTIALITY)) {
			if (!confidentiality)
				throw new AuthenticationException("Confidentiality is mandatory but was not chosen");
		}
		int blockSize = 0;
		if (chosenConfidentialityAlgorithm != null) {
			final IBlockCipher cipher = CipherFactory.getInstance(chosenConfidentialityAlgorithm);
			if (cipher != null)
				blockSize = cipher.defaultBlockSize();
			else // should not happen
				throw new AuthenticationException(
						"Confidentiality algorithm (" + chosenConfidentialityAlgorithm + ") not available");
		}
		sIV = new byte[blockSize];
		if (blockSize > 0)
			getDefaultPRNG().nextBytes(sIV);
	}

	@Override
	@SuppressWarnings("unused")
	protected void resetMechanism() throws SaslException {
		s = null;
		A = B = null;
		K = null;
		inMac = outMac = null;
		inCipher = outCipher = null;
		sid = null;
	}

	private byte[] sendEvidence(final byte[] input) throws SaslException {
		// Client send A, M1, o, cIV
		final InputBuffer frameIn = new InputBuffer(input);
		final byte[] M1;
		try {
			A = frameIn.getMPI(); // Extract client's ephemeral public key
			M1 = frameIn.getOS(); // Extract evidence
			o = frameIn.getText(); // Extract client's options list
			cIV = frameIn.getOS(); // Extract client's IV
		} catch (IOException x) {
			if (x instanceof SaslException)
				throw (SaslException) x;
			throw new AuthenticationException("sendEvidence()", x);
		}
		// Parse client's options and set security layer variables
		parseO(o);
		// ----------------------------------------------------------------------
		try {
			final OutgoingMessage out = new OutgoingMessage();
			out.writeMPI(A);
			final IncomingMessage in = new IncomingMessage(out.toByteArray());
			serverHandler.processMessage(in);
			K = serverHandler.getSharedSecret();
		} catch (KeyAgreementException x) {
			throw new SaslException("sendEvidence()", x);
		}
		// ----------------------------------------------------------------------
		final byte[] expected;
		try {
			expected = srp.generateM1(N, g, U, s, A, B, K, authorizationID, L, cn, cCB);
		} catch (UnsupportedEncodingException x) {
			throw new AuthenticationException("sendEvidence()", x);
		}
		// Verify client evidence
		if (!Arrays.equals(M1, expected))
			throw new AuthenticationException("M1 mismatch");
		setupSecurityServices(true);
		final byte[] M2;
		try {
			M2 = srp.generateM2(A, M1, K, U, authorizationID, o, sid, ttl, cIV, sIV, channelBinding);
		} catch (UnsupportedEncodingException x) {
			throw new AuthenticationException("sendEvidence()", x);
		}
		final OutputBuffer frameOut = new OutputBuffer();
		try {
			frameOut.setOS(M2);
			frameOut.setOS(sIV);
			frameOut.setEOS(sid);
			frameOut.setScalar(4, ttl);
			frameOut.setEOS(channelBinding);
		} catch (IOException x) {
			if (x instanceof SaslException)
				throw (SaslException) x;
			throw new AuthenticationException("sendEvidence()", x);
		}
		final byte[] result = frameOut.encode();
		return result;
	}

	private byte[] sendProtocolElements(final byte[] input) throws SaslException {
		// Client send U, I, sid, cn
		final InputBuffer frameIn = new InputBuffer(input);
		try {
			U = frameIn.getText(); // Extract username
			authorizationID = frameIn.getText(); // Extract authorisation ID
			sid = frameIn.getEOS();
			cn = frameIn.getOS();
			cCB = frameIn.getEOS();
		} catch (IOException x) {
			if (x instanceof SaslException)
				throw (SaslException) x;
			throw new AuthenticationException("sendProtocolElements()", x);
		}
		// do/can we re-use?
		if (ServerStore.instance().isAlive(sid)) {
			final SecurityContext ctx = ServerStore.instance().restoreSession(sid);
			srp = SRP.instance(ctx.getMdName());
			K = ctx.getK();
			cIV = ctx.getClientIV();
			sIV = ctx.getServerIV();
			replayDetection = ctx.hasReplayDetection();
			inCounter = ctx.getInCounter();
			outCounter = ctx.getOutCounter();
			inMac = ctx.getInMac();
			outMac = ctx.getOutMac();
			inCipher = ctx.getInCipher();
			outCipher = ctx.getOutCipher();
			if (sn == null || sn.length != 16)
				sn = new byte[16];
			getDefaultPRNG().nextBytes(sn);
			setupSecurityServices(false);
			final OutputBuffer frameOut = new OutputBuffer();
			try {
				frameOut.setScalar(1, 0xFF);
				frameOut.setOS(sn);
				frameOut.setEOS(channelBinding);
			} catch (IOException x) {
				if (x instanceof SaslException)
					throw (SaslException) x;
				throw new AuthenticationException("sendProtocolElements()", x);
			}
			final byte[] result = frameOut.encode();
			return result;
		} else { // new session
			authenticator.activate(properties);
			// -------------------------------------------------------------------
			final HashMap<String, Object> mapB = new HashMap<>();
			mapB.put(SRP6KeyAgreement.HASH_FUNCTION, srp.getAlgorithm());
			mapB.put(SRP6KeyAgreement.HOST_PASSWORD_DB, authenticator);
			try {
				serverHandler.init(mapB);
				OutgoingMessage out = new OutgoingMessage();
				out.writeString(U);
				IncomingMessage in = new IncomingMessage(out.toByteArray());
				out = serverHandler.processMessage(in);
				in = new IncomingMessage(out.toByteArray());
				N = in.readMPI();
				g = in.readMPI();
				s = in.readMPI().toByteArray();
				B = in.readMPI();
			} catch (KeyAgreementException x) {
				throw new SaslException("sendProtocolElements()", x);
			}
			// -------------------------------------------------------------------
			// The server creates an options list (L), which consists of a
			// comma-separated list of option strings that specify the security
			// service options the server supports.
			L = createL();
			final OutputBuffer frameOut = new OutputBuffer();
			try {
				frameOut.setScalar(1, 0x00);
				frameOut.setMPI(N);
				frameOut.setMPI(g);
				frameOut.setOS(s);
				frameOut.setMPI(B);
				frameOut.setText(L);
			} catch (IOException x) {
				if (x instanceof SaslException)
					throw (SaslException) x;
				throw new AuthenticationException("sendProtocolElements()", x);
			}
			final byte[] result = frameOut.encode();
			return result;
		}
	}

	private void setupSecurityServices(final boolean newSession) throws SaslException {
		complete = true; // signal end of authentication phase
		if (newSession) {
			outCounter = inCounter = 0;
			// instantiate cipher if confidentiality protection filter is active
			if (chosenConfidentialityAlgorithm != null) {
				inCipher = CALG.getInstance(chosenConfidentialityAlgorithm);
				outCipher = CALG.getInstance(chosenConfidentialityAlgorithm);
			}
			// instantiate hmacs if integrity protection filter is active
			if (chosenIntegrityAlgorithm != null) {
				inMac = IALG.getInstance(chosenIntegrityAlgorithm);
				outMac = IALG.getInstance(chosenIntegrityAlgorithm);
			}
			// generate a new sid if at least integrity is used
			sid = (inMac != null ? ServerStore.getNewSessionID() : new byte[0]);
		} else // same session new keys
			K = srp.generateKn(K, cn, sn);

		final KDF kdf = KDF.getInstance(K);
		// initialise in/out ciphers if confidentaility protection is used
		if (inCipher != null) {
			outCipher.init(kdf, sIV, Direction.FORWARD);
			inCipher.init(kdf, cIV, Direction.REVERSED);
		}
		// initialise in/out macs if integrity protection is used
		if (inMac != null) {
			outMac.init(kdf);
			inMac.init(kdf);
		}
		if (sid != null && sid.length != 0) { // update the security context and save in map
			ServerStore.instance().cacheSession(ttl, new SecurityContext(srp.getAlgorithm(), sid, K, cIV, sIV,
					replayDetection, inCounter, outCounter, inMac, outMac, inCipher, outCipher));
		}
	}
}
