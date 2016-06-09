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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;

import org.eclipse.jetty.alpn.ALPN;
import org.eclipse.jetty.io.ssl.ALPNServerProvider;
import org.eclipse.jetty.io.ssl.ClientHelloProcessor;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class ClientHelloALPNProcessor extends ClientHelloALPNParser implements ClientHelloProcessor
{
    private static final Logger LOG = Log.getLogger(ClientHelloALPNProcessor.class);

    private String tlsProtocol;
    private List<String> cipherSuites;
    private List<String> protocols;

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
    public boolean process(ByteBuffer buffer, SSLEngine sslEngine) throws SSLException
    {
        if (!parse(buffer))
            return false;

        SSLParameters sslParameters = sslEngine.getSSLParameters();

        List<String> cipherSuites = new ArrayList<>();
        Collections.addAll(cipherSuites, sslParameters.getCipherSuites());
        cipherSuites.retainAll(this.cipherSuites);
        if (LOG.isDebugEnabled())
            LOG.debug("ALPN processing negotiated cipher suites: {}", cipherSuites);

        ALPNServerProvider provider = (ALPNServerProvider)ALPN.get(sslEngine);

        String protocol = null;
        for (Iterator<String> iterator = cipherSuites.iterator(); iterator.hasNext();)
        {
            try
            {
                String cipherSuite = iterator.next();
                String selected = provider.select(new ALPNServerProvider.Info(tlsProtocol, cipherSuite, protocols));
                if (selected == null)
                {
                    iterator.remove();
                }
                else
                {
                    // Remember the first negotiated protocol.
                    if (protocol == null)
                        protocol = selected;

                    // Only keep ciphers for the same protocol.
                    if (!protocol.equals(selected))
                        iterator.remove();
                }
            }
            catch (Throwable x)
            {
                LOG.ignore(x);
                iterator.remove();
            }
        }

        if (protocol == null)
            throw new SSLHandshakeException("no_application_protocol");

        sslParameters.setCipherSuites(cipherSuites.toArray(new String[0]));
        sslParameters.setApplicationProtocols(new String[]{protocol});
        sslEngine.setSSLParameters(sslParameters);
        if (LOG.isDebugEnabled())
            LOG.debug("ALPN processing negotiated protocol/ciphers {}/{}", protocol, cipherSuites);
        return true;
    }
}
