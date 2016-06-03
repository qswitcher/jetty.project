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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class CipherName
{
    private static Map<Integer, String> names = new HashMap<>();

    static
    {
        try
        {
            Class<?> cipherSuiteClass = ClassLoader.getSystemClassLoader().loadClass("sun.security.ssl.CipherSuite");
            Field idMapField = cipherSuiteClass.getDeclaredField("idMap");
            idMapField.setAccessible(true);
            Field nameField = cipherSuiteClass.getDeclaredField("name");
            nameField.setAccessible(true);

            @SuppressWarnings("unchecked")
            Map<Integer, Object> map = (Map<Integer, Object>)idMapField.get(null);
            for (Map.Entry<Integer, Object> entry : map.entrySet())
                names.put(entry.getKey(), (String)nameField.get(entry.getValue()));
        }
        catch (Exception x)
        {
            throw new Error(x);
        }
    }

    private CipherName()
    {
    }

    public static Optional<String> from(byte code1, byte code2)
    {
        int code = ((code1 & 0xFF) << 8) + (code2 & 0xFF);
        return from(code);
    }

    public static Optional<String> from(int code)
    {
        return Optional.ofNullable(names.get(code));
    }
}
