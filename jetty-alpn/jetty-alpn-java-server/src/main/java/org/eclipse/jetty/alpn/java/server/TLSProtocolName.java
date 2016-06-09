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

public class TLSProtocolName
{
    public static String from(int tlsVersion)
    {
        switch (tlsVersion)
        {
            case 0x0300:
                return "SSLv3";
            case 0x0301:
                return "TLSv1";
            case 0x0302:
                return "TLSv1.1";
            case 0x0303:
                return "TLSv1.2";
            default:
                throw new IllegalArgumentException("Invalid TLS Protocol 0x" + Integer.toHexString(tlsVersion));
        }
    }
}
