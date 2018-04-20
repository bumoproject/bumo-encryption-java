package org.bumo.encryption.utils.http;


import javax.net.ssl.SSLSession;


public class Verifier implements javax.net.ssl.HostnameVerifier {

	public boolean verify(String hostname, SSLSession session) {
		return true;
	}

}
