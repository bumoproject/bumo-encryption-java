// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package io.bumo.encryption.utils.jni;

/**
 * A {@code LibraryLoader} attempts to load the appropriate native library
 * for the current platform.
 *
 * @author bumo
 */
public interface LibraryLoader {
    /**
     * Load a native library, and optionally verify any signatures.
     *
     * @param name      Name of the library to load.
     * @param verify    Verify signatures if signed.
     *
     * @return true if the library was successfully loaded.
     */
    boolean load(String name, boolean verify);
}
