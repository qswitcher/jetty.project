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
import java.util.List;

import org.eclipse.jetty.util.TypeUtil;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;

public class ClientHelloALPNParserTest
{
    @Test
    public void testClientHelloParser() throws Exception
    {
        // Bytes captured via Wireshark from a browser.
        byte[] bytes = TypeUtil.fromHexString("16030100b8010000b40303b18da832af81c989018f2f82b8ed7d6d2e386871a64c2dc9efef77e124a5a09f000016c02bc02fc00ac009c013c01400330039002f0035000a0100007500000010000e00000b776562746964652e636f6d00170000ff01000100000a00080006001700180019000b00020100002300003374000000100017001502683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202");
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        ClientHelloALPNParser parser = new ClientHelloALPNParser()
        {
            @Override
            protected void onClientHello(String tlsProtocol, List<String> ciphers, List<String> alpnProtocols)
            {
                Assert.assertEquals("TLSv1.2", tlsProtocol);
                Assert.assertFalse(ciphers.isEmpty());
                Assert.assertThat(alpnProtocols, Matchers.hasItems("http/1.1", "h2"));
            }
        };
        Assert.assertTrue(parser.parse(buffer));
    }
}
