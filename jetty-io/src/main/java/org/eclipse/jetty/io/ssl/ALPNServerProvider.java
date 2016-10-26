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

package org.eclipse.jetty.io.ssl;

import java.util.List;

public interface ALPNServerProvider
{
    public String select(Info info);

    public void selected(String protocol);
    
    public void sort(List<String> protocols);

    public static class Info
    {
        private final String tlsProtocol;
        private final String cipherSuite;
        private final List<String> protocols;

        public Info(String tlsProtocol, String cipherSuite, List<String> protocols)
        {
            this.tlsProtocol = tlsProtocol;
            this.cipherSuite = cipherSuite;
            this.protocols = protocols;
        }

        public String getTLSProtocol()
        {
            return tlsProtocol;
        }

        public String getCipherSuite()
        {
            return cipherSuite;
        }

        public List<String> getProtocols()
        {
            return protocols;
        }
    }
}
