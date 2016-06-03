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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.eclipse.jetty.util.TypeUtil;

public class ClientHelloParser
{
    private State state = State.MESSAGE_TYPE;
    private List<String> ciphers = new ArrayList<>();
    private List<String> protocols = new ArrayList<>();
    private int cursor;
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
                    consume(buffer, State.CLIENT_HELLO_TIMESTAMP, 4);
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
                        Optional<String> cipherName = CipherName.from(cipher);
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
                            return true;
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
                            return true;
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

    public static void main(String[] args)
    {
        byte[] bytes = TypeUtil.fromHexString("16030100b8010000b40303b18da832af81c989018f2f82b8ed7d6d2e386871a64c2dc9efef77e124a5a09f000016c02bc02fc00ac009c013c01400330039002f0035000a0100007500000010000e00000b776562746964652e636f6d00170000ff01000100000a00080006001700180019000b00020100002300003374000000100017001502683208737064792f332e3108687474702f312e31000500050100000000000d001600140401050106010201040305030603020304020202");
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        ClientHelloParser parser = new ClientHelloParser();
        if (parser.parse(buffer))
        {
            System.err.println("CIPHERS: " + parser.ciphers);
            System.err.println("PROTOCOLS: " + parser.protocols);
        }
    }
}
