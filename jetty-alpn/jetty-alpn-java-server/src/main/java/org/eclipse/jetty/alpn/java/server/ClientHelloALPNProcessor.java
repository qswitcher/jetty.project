//
//  ========================================================================
//  Copyright (c) 1995-2016 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.alpn.java.server;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.eclipse.jetty.alpn.ALPN;
import org.eclipse.jetty.io.ssl.ALPNServerProvider;
import org.eclipse.jetty.io.ssl.ClientHelloProcessor;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class ClientHelloALPNProcessor extends ClientHelloALPNParser implements ClientHelloProcessor
{
    private static final Logger LOG = Log.getLogger(ClientHelloALPNProcessor.class);

    private final List<CipherProtocolPair> pairs = new ArrayList<>();
    private String tlsProtocol;
    private List<String> cipherSuites;
    private List<String> protocols;
    private ALPNServerProvider provider;

    @Override
    protected void onClientHello(String tlsProtocol, List<String> cipherSuites, List<String> alpnProtocols)
    {
        this.tlsProtocol = tlsProtocol;
        this.cipherSuites = cipherSuites;
        this.protocols = alpnProtocols;
        if (LOG.isDebugEnabled())
            LOG.debug("Parsed {} ClientHello, alpn={}", tlsProtocol, alpnProtocols);
    }

    @Override
    public boolean preProcess(ByteBuffer buffer, SSLEngine sslEngine) throws SSLException
    {
        if (!parse(buffer))
            return false;

        provider = (ALPNServerProvider)ALPN.get(sslEngine);

        List<String> cipherSuites = new ArrayList<>();
        Collections.addAll(cipherSuites, sslEngine.getEnabledCipherSuites());
        cipherSuites.retainAll(this.cipherSuites);
        if (LOG.isDebugEnabled())
            LOG.debug("ALPN processing negotiated cipher suites: {}", cipherSuites);

        for (Iterator<String> iterator = cipherSuites.iterator(); iterator.hasNext();)
        {
            try
            {
                String cipherSuite = iterator.next();
                String protocol = provider.select(new ALPNServerProvider.Info(tlsProtocol, cipherSuite, protocols));
                if (protocol == null)
                {
                    iterator.remove();
                }
                else
                {
                    pairs.add(new CipherProtocolPair(cipherSuite, protocol));
                }
            }
            catch (Throwable x)
            {
                LOG.ignore(x);
                iterator.remove();
            }
        }

        if (pairs.isEmpty())
            throw new SSLHandshakeException("no_application_protocol");

        return true;
    }

    @Override
    public void postProcess(SSLEngine sslEngine) throws SSLException
    {
        SSLSession session = sslEngine.getHandshakeSession();

        String tlsProtocol = session.getProtocol();
        if (!tlsProtocol.equals(this.tlsProtocol))
            throw new SSLHandshakeException("no_tls_protocol");
        String cipherSuite = session.getCipherSuite();

        List<CipherProtocolPair> pairs = this.pairs.stream()
                .filter(pair -> cipherSuite.equals(pair.cipherSuite))
                .collect(Collectors.toList());
        if (pairs.isEmpty())
            throw new SSLHandshakeException("no_cipher_suite");

        String protocol = pairs.get(0).protocol;
        List<String> cipherSuites = pairs.stream()
                .filter(pair -> protocol.equals(pair.protocol))
                .map(pair -> pair.cipherSuite)
                .collect(Collectors.toList());

        provider.selected(protocol);

        SSLParameters sslParameters = sslEngine.getSSLParameters();
        sslParameters.setCipherSuites(cipherSuites.toArray(new String[0]));
        sslParameters.setApplicationProtocols(new String[]{protocol});
        sslEngine.setSSLParameters(sslParameters);
        if (LOG.isDebugEnabled())
            LOG.debug("ALPN processing negotiated protocol/ciphers {}/{}", protocol, cipherSuites);
    }

    private static class CipherProtocolPair
    {
        private final String cipherSuite;
        private final String protocol;

        private CipherProtocolPair(String cipherSuite, String protocol)
        {
            this.cipherSuite = cipherSuite;
            this.protocol = protocol;
        }
    }
}
