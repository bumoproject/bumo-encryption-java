package io.bumo.encryption.crypto.keystore.entity;

public class ScryptParamsEty {
	private int n;
	private int p;
	private int r;
	private String salt;
	public int getN() {
		return n;
	}
	public void setN(int n) {
		this.n = n;
	}
	public int getP() {
		return p;
	}
	public void setP(int p) {
		this.p = p;
	}
	public int getR() {
		return r;
	}
	public void setR(int r) {
		this.r = r;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	
	
}
