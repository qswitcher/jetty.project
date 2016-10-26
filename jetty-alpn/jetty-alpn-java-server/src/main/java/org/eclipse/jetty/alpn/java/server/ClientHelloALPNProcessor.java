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
    private List<String> ciphersOffered;
    private List<String> protocolsOffered;
    private ALPNServerProvider provider;

    @Override
    protected void onClientHello(String tlsProtocol, List<String> cipherSuites, List<String> alpnProtocols)
    {
        this.tlsProtocol = tlsProtocol;
        this.ciphersOffered = cipherSuites;
        this.protocolsOffered = alpnProtocols;
        if (LOG.isDebugEnabled())
            LOG.debug("Parsed {} ClientHello, alpn={}", tlsProtocol, alpnProtocols);
    }

    @Override
    public boolean preProcess(ByteBuffer buffer, SSLEngine sslEngine) throws SSLException
    {
        // This is called as the ClientHello frame is received.

        // Have we parsed the entire hello frame?
        if (!parse(buffer))
            return false;

        // Get the servers ALPN provider
        provider = (ALPNServerProvider)ALPN.get(sslEngine);

        // Calculate the acceptable ciphers, which are the enabled ciphers
        // with only the offered ciphers retained
        List<String> ciphers = new ArrayList<>();
        Collections.addAll(ciphers, sslEngine.getEnabledCipherSuites());
        ciphers.retainAll(this.ciphersOffered);
        if (LOG.isDebugEnabled())
            LOG.debug("ALPN processing negotiated cipher suites: {}", ciphers);

        // We now need to select an application protocol, but we cannot
        // predict what cipher will be negotiated unless we replicate or somehow
        // access the chooseCipherSuite code at:
        //    http://hg.openjdk.java.net/jdk9/jdk9/jdk/file/7b0b28ceca62/src/java.base/share/classes/sun/security/ssl/ServerHandshaker.java#l1143
        // which is itself a loop over the even more complex code of trySetCipherSuite:
        //    http://hg.openjdk.java.net/jdk9/jdk9/jdk/file/7b0b28ceca62/src/java.base/share/classes/sun/security/ssl/ServerHandshaker.java#l1207
        // which uses non public APIs so it cannot be replicated!  This method also calls
        //    X509KeyManager#chooseServerAlias
        // which selects the certificate to use, potentially using SNI extensions or other user supplied logic
        //
        // In summary, this is complex code thats call both private APIs and 
        // user extensible X509KeyManager methods that cannot be predicted.
        // Without knowing the negotiated cipher, we cannot pick a single application protocol
        // instead we can only look at which application protocol would be selected for each acceptable cipher
        for (Iterator<String> iterator = ciphers.iterator(); iterator.hasNext();)
        {
            try
            {
                String cipherSuite = iterator.next();

                // We ask our ALPN provider what protocol they would select for the TLS protocol, cipher 
                // and given list of offered protocols.  This is a call back to our connection factory,
                // which probably will implements HTTP2 TLS requirements, but may be arbitrary logic in future.
                String protocol = provider.select(new ALPNServerProvider.Info(tlsProtocol, cipherSuite, protocolsOffered));

                // If there is no acceptable protocol for the cipher
                if (protocol == null)
                {
                    // the cipher is not acceptable
                    iterator.remove();
                }
                else
                {
                    // We have an acceptable cipher protocol pair!
                    pairs.add(new CipherProtocolPair(cipherSuite, protocol));
                }
            }
            catch (Throwable x)
            {
                LOG.ignore(x);
                iterator.remove();
            }
        }

        // Do we have any acceptable cipher protocol pairs?
        if (pairs.isEmpty())
            throw new SSLHandshakeException("no_application_protocol");

        // Set the acceptable ciphers on the SslEngine
        SSLParameters sslParameters = sslEngine.getSSLParameters();
        sslParameters.setCipherSuites(ciphers.toArray(new String[ciphers.size()]));

        // Set the application protocol(s) on the SslEngine
        // Ideally we would like to tell it our cipherProtocol pairs, but API does not support that!
        // We must pick only one application protocol, even if that is not acceptable for all ciphers!
        List<String> protocols = new ArrayList<>(pairs.stream().map(CipherProtocolPair::getProtocol).collect(Collectors.toSet()));
//        provider.sort(protocols); // Broken
        sslParameters.setApplicationProtocols(new String[]{protocols.get(0)});

        // Update the SslEngine with the parameters.
        sslEngine.setSSLParameters(sslParameters);

        return true;
    }

    @Override
    public void postProcess(SSLEngine sslEngine) throws SSLException
    {
        // This is called on the first NEED_WRAP status after parsing
        // the ClientHello, which will be after the cipher has been
        // selected by a NEED_TASK call, but before the ClientHello
        // response is generated by the wrap call.

        SSLSession session = sslEngine.getHandshakeSession();
        SSLParameters sslParameters = sslEngine.getSSLParameters();

        // What TLS protocol was negotiated?  Check it was what we pre-processed
        String tlsProtocol = session.getProtocol();
        if (!tlsProtocol.equals(this.tlsProtocol))
            throw new SSLHandshakeException("no_tls_protocol");

        // What cipher was negotiated?  Check we have a cipher protocol pair for it 
        String cipherSuite = session.getCipherSuite();
        List<CipherProtocolPair> pairs = this.pairs.stream()
                .filter(pair -> cipherSuite.equals(pair.getCipherSuite()))
                .collect(Collectors.toList());
        if (pairs.isEmpty())
            throw new SSLHandshakeException("no_cipher_suite");

        // Is there an cipher protocol pair for the pre configured application protocol?
        String protocol = sslParameters.getApplicationProtocols()[0];
        if (pairs.stream().noneMatch(pair -> protocol.equals(pair.protocol)))
        {
            // This is a rare but possible case!

            // TODO we would like to do this
            List<String> protocols = new ArrayList<>(pairs.stream().map(CipherProtocolPair::getProtocol).collect(Collectors.toSet()));
            provider.sort(protocols);
            String next = protocols.get(0);
            sslParameters.setApplicationProtocols(new String[]{next});
            sslEngine.setSSLParameters(sslParameters);

            // TODO but it is ignored, so we have to do
            // create a new SslEngine instance
            // set the application protocol to protocol
            // replay the client hello
            // check everything is the same
            // replace the sslEngine in our calling scope with the new sslEngine
        }

        // Signal the application protocol choice
        provider.selected(protocol);
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

        public String getCipherSuite()
        {
            return cipherSuite;
        }

        public String getProtocol()
        {
            return protocol;
        }
    }
}
