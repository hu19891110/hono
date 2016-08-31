/**
 * Copyright (c) 2016 Bosch Software Innovations GmbH.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Bosch Software Innovations GmbH - initial creation
 */
package org.eclipse.hono.authentication;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Objects;

import org.apache.qpid.proton.engine.Record;
import org.apache.qpid.proton.engine.Sasl;
import org.apache.qpid.proton.engine.Sasl.SaslOutcome;
import org.apache.qpid.proton.engine.Transport;
import org.eclipse.hono.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.vertx.core.Vertx;
import io.vertx.core.net.NetSocket;
import io.vertx.proton.ProtonConnection;
import io.vertx.proton.sasl.ProtonSaslAuthenticator;

/**
 * A PLAIN SASL authenticator that accepts all credentials.
 *
 */
public final class AcceptAllAuthenticator implements ProtonSaslAuthenticator {

    private static final      String PLAIN = "PLAIN";
    private static final      String OAUTH_BEARER = "OAUTHBEARER";
    private static final      Logger LOG = LoggerFactory.getLogger(AcceptAllAuthenticator.class);
    private final Vertx       vertx;
    private Sasl              sasl;
    private boolean           succeeded;
    private ProtonConnection  protonConnection;

    /**
     * Creates a new authenticator for a Vertx environment.
     */
    public AcceptAllAuthenticator(final Vertx vertx) {
        this.vertx = Objects.requireNonNull(vertx);
    }

    @Override
    public void init(final NetSocket socket, final ProtonConnection protonConnection, final Transport transport) {
        this.protonConnection = protonConnection;
        this.sasl = transport.sasl();
        sasl.server();
        sasl.allowSkip(false);
        sasl.setMechanisms(PLAIN);
    }

    @Override
    public boolean process() {
        String[] remoteMechanisms = sasl.getRemoteMechanisms();

        if (remoteMechanisms.length > 0) {
            String chosenMechanism = remoteMechanisms[0];
            LOG.debug("client wants to use {} SASL mechanism", chosenMechanism);

            if (PLAIN.equals(chosenMechanism)) {
                succeeded = evaluatePlainResponse(sasl, protonConnection.attachments());
            }

            if (succeeded) {
                sasl.done(SaslOutcome.PN_SASL_OK);
            } else {
                sasl.done(SaslOutcome.PN_SASL_AUTH);
            }

            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean succeeded() {
        return succeeded;
    }

    private boolean evaluatePlainResponse(final Sasl sasl, final Record attachments) {
        byte[] response = new byte[sasl.pending()];
        sasl.recv(response, 0, response.length);

        // Per https://tools.ietf.org/html/rfc4616 the PLAIN message format is: [authzid] UTF8NUL authcid UTF8NUL passwd
        // Break initial response into its constituent parts.
        int authzidTerminatorPos = findNullPosition(response, 0);
        if (authzidTerminatorPos < 0) {
            // Invalid PLAIN encoding, authzid null terminator not found
            return false;
        }

        int authcidTerminatorPos = findNullPosition(response, authzidTerminatorPos + 1);
        if (authcidTerminatorPos < 0) {
            // Invalid PLAIN encoding, authcid null terminator not found
            return false;
        }

        if (authcidTerminatorPos == response.length - 1) {
            // Invalid PLAIN encoding, no password present
            return false;
        }

        // Grab the authcid and password (ignoring authzid if present)
        final String authcid = new String(response, authzidTerminatorPos + 1, authcidTerminatorPos - authzidTerminatorPos - 1,
                StandardCharsets.UTF_8);
        final String passwd = new String(response, authcidTerminatorPos + 1, response.length - authcidTerminatorPos - 1,
                StandardCharsets.UTF_8);
        LOG.debug("client uses credentials [{}/{}]", authcid, passwd);
        // Now verify the given credentials
//        if (GOOD_USER.equals(authcid) && PASSWD.equals(passwd)) {
//            // Success
//            return true;
//        }
        attachments.set(Constants.KEY_CLIENT_PRINCIPAL, Principal.class, new Principal() {

            @Override
            public String getName() {
                return authcid;
            }
        });

        return true;
    }

    private int findNullPosition(byte[] response, int startPosition) {
        int position = startPosition;
        while (position < response.length) {
            if (response[position] == (byte) 0) {
                return position;
            }
            position++;
        }
        return -1;
    }
}
