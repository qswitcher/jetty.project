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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ClientHelloALPNParser
{
    private State state = State.MESSAGE_TYPE;
    private List<String> ciphers = new ArrayList<>();
    private List<String> protocols = new ArrayList<>();
    private int cursor;
    private int tlsVersion;
    private int ciphersLength;
    private int cipher;
    private int extensionsLength;
    private int extensionType;
    private int extensionLength;
    private byte[] protocolBytes;

    public boolean parse(ByteBuffer buffer)
    {
        while (buffer.hasRemaining())
        {
            switch (state)
            {
                case MESSAGE_TYPE:
                {
                    int messageType = buffer.get() & 0xFF;
                    if (messageType != 0x16)
                        throw new IllegalStateException();
                    state = State.PROTOCOL_VERSION;
                    cursor = 2;
                    break;
                }
                case PROTOCOL_VERSION:
                {
                    consume(buffer, State.MESSAGE_LENGTH, 2);
                    break;
                }
                case MESSAGE_LENGTH:
                {
                    consume(buffer, State.HANDSHAKE_TYPE, 0);
                    break;
                }
                case HANDSHAKE_TYPE:
                {
                    int handshakeType = buffer.get() & 0xFF;
                    if (handshakeType != 0x01)
                        throw new IllegalStateException();
                    state = State.HANDSHAKE_LENGTH;
                    cursor = 3;
                    break;
                }
                case HANDSHAKE_LENGTH:
                {
                    consume(buffer, State.CLIENT_HELLO_VERSION, 2);
                    break;
                }
                case CLIENT_HELLO_VERSION:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    tlsVersion += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        state = State.CLIENT_HELLO_TIMESTAMP;
                        cursor = 4;
                    }
                    break;
                }
                case CLIENT_HELLO_TIMESTAMP:
                {
                    consume(buffer, State.CLIENT_HELLO_RANDOM, 28);
                    break;
                }
                case CLIENT_HELLO_RANDOM:
                {
                    consume(buffer, State.CLIENT_HELLO_SESSION_LENGTH, 0);
                    break;
                }
                case CLIENT_HELLO_SESSION_LENGTH:
                {
                    int sessionLength = buffer.get() & 0xFF;
                    if (sessionLength == 0)
                    {
                        state = State.CLIENT_HELLO_CIPHERS_LENGTH;
                        cursor = 2;
                    }
                    else
                    {
                        state = State.CLIENT_HELLO_SESSION;
                        cursor = sessionLength;
                    }
                    break;
                }
                case CLIENT_HELLO_SESSION:
                {
                    consume(buffer, State.CLIENT_HELLO_CIPHERS_LENGTH, 2);
                    break;
                }
                case CLIENT_HELLO_CIPHERS_LENGTH:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    ciphersLength += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        state = State.CLIENT_HELLO_CIPHERS;
                        cursor = 2;
                    }
                    break;
                }
                case CLIENT_HELLO_CIPHERS:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    cipher += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        Optional<String> cipherName = CipherSuiteName.from(cipher);
                        cipherName.map(ciphers::add);
                        cipher = 0;
                        ciphersLength -= 2;
                        if (ciphersLength == 0)
                        {
                            state = State.CLIENT_HELLO_COMPRESSION_LENGTH;
                            cursor = 1;
                        }
                        else
                        {
                            cursor = 2;
                        }
                    }
                    break;
                }
                case CLIENT_HELLO_COMPRESSION_LENGTH:
                {
                    int compressionLength = buffer.get() & 0xFF;
                    if (compressionLength == 0)
                    {
                        state = State.CLIENT_HELLO_EXTENSIONS_LENGTH;
                        cursor = 2;
                    }
                    else
                    {
                        state = State.CLIENT_HELLO_COMPRESSION;
                        cursor = compressionLength;
                    }
                    break;
                }
                case CLIENT_HELLO_COMPRESSION:
                {
                    consume(buffer, State.CLIENT_HELLO_EXTENSIONS_LENGTH, 2);
                    break;
                }
                case CLIENT_HELLO_EXTENSIONS_LENGTH:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    extensionsLength += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        state = State.CLIENT_HELLO_EXTENSION_TYPE;
                        cursor = 2;
                    }
                    break;
                }
                case CLIENT_HELLO_EXTENSION_TYPE:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    extensionType += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        state = State.CLIENT_HELLO_EXTENSION_LENGTH;
                        cursor = 2;
                        extensionsLength -= 2;
                    }
                    break;
                }
                case CLIENT_HELLO_EXTENSION_LENGTH:
                {
                    int currByte = buffer.get() & 0xFF;
                    --cursor;
                    extensionLength += currByte << (8 * cursor);
                    if (cursor == 0)
                    {
                        extensionsLength -= 2;
                        if (extensionLength == 0)
                        {
                            state = State.CLIENT_HELLO_EXTENSION_TYPE;
                            cursor = 2;
                            extensionType = 0;
                        }
                        else
                        {
                            if (extensionType == 0x10)
                            {
                                state = State.CLIENT_HELLO_ALPN_LENGTH;
                                cursor = 2;
                            }
                            else
                            {
                                state = State.CLIENT_HELLO_EXTENSION;
                                cursor = extensionLength;
                            }
                        }
                    }
                    break;
                }
                case CLIENT_HELLO_EXTENSION:
                {
                    if (consume(buffer, State.CLIENT_HELLO_EXTENSION_TYPE, 2))
                    {
                        extensionsLength -= extensionLength;
                        extensionType = 0;
                        extensionLength = 0;
                        if (extensionsLength == 0)
                        {
                            onClientHello(TLSProtocolName.from(tlsVersion), new ArrayList<>(ciphers), new ArrayList<>(protocols));
                            return true;
                        }
                    }
                    break;
                }
                case CLIENT_HELLO_ALPN_LENGTH:
                {
                    if (consume(buffer, State.CLIENT_HELLO_ALPN_PROTOCOL_LENGTH, 1))
                    {
                        extensionsLength -= 2;
                        extensionLength -= 2;
                    }
                    break;
                }
                case CLIENT_HELLO_ALPN_PROTOCOL_LENGTH:
                {
                    int protocolLength = buffer.get() & 0xFF;
                    --extensionsLength;
                    --extensionLength;
                    state = State.CLIENT_HELLO_ALPN_PROTOCOL;
                    cursor = protocolLength;
                    protocolBytes = new byte[protocolLength];
                    break;
                }
                case CLIENT_HELLO_ALPN_PROTOCOL:
                {
                    protocolBytes[protocolBytes.length - cursor] = buffer.get();
                    --extensionsLength;
                    --extensionLength;
                    --cursor;
                    if (cursor == 0)
                    {
                        protocols.add(new String(protocolBytes, StandardCharsets.US_ASCII));
                        state = State.CLIENT_HELLO_ALPN_PROTOCOL_LENGTH;
                        if (extensionLength == 0)
                        {
                            onClientHello(TLSProtocolName.from(tlsVersion), new ArrayList<>(ciphers), new ArrayList<>(protocols));
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean consume(ByteBuffer buffer, State nextState, int nextCursor)
    {
        buffer.get();
        --cursor;
        if (cursor == 0)
        {
            state = nextState;
            cursor = nextCursor;
            return true;
        }
        return false;
    }

    protected void onClientHello(String tlsProtocol, List<String> ciphers, List<String> alpnProtocols)
    {
    }

    private enum State
    {
        MESSAGE_TYPE,
        PROTOCOL_VERSION,
        MESSAGE_LENGTH,
        HANDSHAKE_TYPE,
        HANDSHAKE_LENGTH,
        CLIENT_HELLO_VERSION,
        CLIENT_HELLO_TIMESTAMP,
        CLIENT_HELLO_RANDOM,
        CLIENT_HELLO_SESSION_LENGTH,
        CLIENT_HELLO_SESSION,
        CLIENT_HELLO_CIPHERS_LENGTH,
        CLIENT_HELLO_CIPHERS,
        CLIENT_HELLO_COMPRESSION_LENGTH,
        CLIENT_HELLO_COMPRESSION,
        CLIENT_HELLO_EXTENSIONS_LENGTH,
        CLIENT_HELLO_EXTENSION_TYPE,
        CLIENT_HELLO_EXTENSION_LENGTH,
        CLIENT_HELLO_EXTENSION,
        CLIENT_HELLO_ALPN_LENGTH,
        CLIENT_HELLO_ALPN_PROTOCOL_LENGTH,
        CLIENT_HELLO_ALPN_PROTOCOL
    }
}
