package com.froad.sm2testpro.utils

import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray

/**
 * Created by FW on 2017/7/4.
 */
object SM2Util {
    private const val TAG = "SM2Util"
    const val SM2UserId = "31323334353637383132333435363738"
    fun verifySign(publicKey: ByteArray?, sourceData: ByteArray?, signData: ByteArray?): Boolean {
        return verifySign(hexString2ByteArray(SM2UserId), publicKey, sourceData, signData)
    }

    fun verifySign(
        userId: ByteArray?,
        publicKey: ByteArray?,
        sourceData: ByteArray?,
        signData: ByteArray?
    ): Boolean {
        return SM2().sm2VerifySign(userId!!, publicKey, sourceData, signData)
    }

    /**
     * SM2加密
     * @param publicKey
     * @param data
     * @param isC 是否需要将加密结果处理为C加密模式数据，只有为true时type才有效，否则，加密结果为der编码
     * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
     * @return
     */
    fun encrypt(publicKey: ByteArray?, data: ByteArray?, isC: Boolean, type: Int): ByteArray? {
        return SM2().sm2Encrypt(publicKey, data, isC, type)
    }

    /**
     * SM2解密
     * @param privateKey
     * @param encryptedData
     * @param isC 加密数据内容是否为C加密模式数据，只有为true时type才有效，否则，加密内容为der编码
     * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
     * @return
     */
    fun decrypt(
        privateKey: ByteArray?,
        encryptedData: ByteArray?,
        isC: Boolean,
        type: Int
    ): ByteArray? {
        return SM2().sm2Decrypt(privateKey, encryptedData, isC, type)
    }

    fun dealSm2SignResultC(res: ByteArray?): ByteArray? {
        return SM2().dealSm2SignResultC(res)
    }

    fun dealSm2SignResultAdd(res: ByteArray?): ByteArray? {
        return SM2().dealSm2SignResultAdd(res)
    }
}