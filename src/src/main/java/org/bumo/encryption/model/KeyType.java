package org.bumo.encryption.model;

public enum KeyType {
	/**
	 * ED25519算法
	 */
	ED25519, 
	/**
	 * 国家标准SM2算法，用国家推荐的椭圆曲线参数，也是CFCA所用的参数
	 */
	ECCSM2
}
