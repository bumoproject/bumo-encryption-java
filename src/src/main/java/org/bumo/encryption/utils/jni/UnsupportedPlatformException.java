// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package org.bumo.encryption.utils.jni;

/**
 * Exception thrown when the current platform cannot be detected.
 *
 * @author bumo
 */
@SuppressWarnings("serial")
public class UnsupportedPlatformException extends RuntimeException {
    public UnsupportedPlatformException(String s) {
        super(s);
    }
}
