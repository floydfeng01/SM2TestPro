package com.froad.sm2testpro.utils

import com.froad.sm2testpro.utils.FCharUtils.byteConvert32Bytes
import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray
import com.froad.sm2testpro.utils.FCharUtils.int2HexStr
import com.froad.sm2testpro.utils.FCharUtils.intToByte
import org.bc.asn1.*
import org.bc.crypto.generators.ECKeyPairGenerator
import org.bc.crypto.params.ECDomainParameters
import org.bc.crypto.params.ECKeyGenerationParameters
import org.bc.math.ec.ECCurve
import org.bc.math.ec.ECFieldElement
import org.bc.math.ec.ECPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Created by FW on 2017/7/5.
 */
class SM2 {
    val ecc_p: BigInteger
    val ecc_a: BigInteger
    val ecc_b: BigInteger
    val ecc_n: BigInteger
    val ecc_gx: BigInteger
    val ecc_gy: BigInteger
    val ecc_curve: ECCurve
    val ecc_point_g: ECPoint
    val ecc_bc_spec: ECDomainParameters
    val ecc_key_pair_generator: ECKeyPairGenerator
    val ecc_gx_fieldelement: ECFieldElement
    val ecc_gy_fieldelement: ECFieldElement
    fun sm2GetZ(userId: ByteArray, userKey: ECPoint): ByteArray {
        val sm3 = SM3Digest()
        val len = userId.size * 8
        sm3.update((len shr 8 and 0xFF).toByte())
        sm3.update((len and 0xFF).toByte())
        sm3.update(userId, 0, userId.size)
        var p = byteConvert32Bytes(ecc_a)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_b)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_gx)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_gy)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(userKey.x.toBigInteger())
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(userKey.y.toBigInteger())
        sm3.update(p, 0, p!!.size)
        val md = ByteArray(sm3.digestSize)
        sm3.doFinal(md, 0)
        return md
    }

    /**
     * 获取签名摘要
     * @param userId
     * @param smX
     * @param smY
     * @return
     */
    fun sm2GetZSM(userId: ByteArray, smX: String?, smY: String?): ByteArray {
        val sm3 = SM3Digest()
        val len = userId.size * 8
        sm3.update((len shr 8 and 0xFF).toByte())
        sm3.update((len and 0xFF).toByte())
        sm3.update(userId, 0, userId.size)
        var p = byteConvert32Bytes(ecc_a)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_b)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_gx)
        sm3.update(p, 0, p!!.size)
        p = byteConvert32Bytes(ecc_gy)
        sm3.update(p, 0, p!!.size)
        p = hexString2ByteArray(smX!!)
        sm3.update(p, 0, p!!.size)
        p = hexString2ByteArray(smY!!)
        sm3.update(p, 0, p!!.size)
        val md = ByteArray(sm3.digestSize)
        sm3.doFinal(md, 0)
        return md
    }

    /**
     * SM2签名
     * @param md
     * @param userD
     * @param userKey
     * @param sm2Result
     */
    fun sm2Sign(md: ByteArray?, userD: BigInteger, userKey: ECPoint?, sm2Result: SM2Result) {
        val e = BigInteger(1, md)
        var k: BigInteger? = null
        var kp: ECPoint? = null
        var r: BigInteger? = null
        var s: BigInteger? = null
        do {
            do {
                k = userD
                kp = userKey
                println("计算曲线点X1: " + kp!!.x.toBigInteger().toString(16))
                println("计算曲线点Y1: " + kp.y.toBigInteger().toString(16))
                println("")
                r = e.add(kp.x.toBigInteger())
                r = r.mod(ecc_n)
            } while (r == BigInteger.ZERO || r!!.add(k) == ecc_n)
            var da_1 = userD.add(BigInteger.ONE)
            da_1 = da_1.modInverse(ecc_n)
            s = r.multiply(userD)
            s = k!!.subtract(s).mod(ecc_n)
            s = da_1.multiply(s).mod(ecc_n)
        } while (s == BigInteger.ZERO)
        sm2Result.r = r
        sm2Result.s = s
    }

    /**
     * SM2验证签名核心方法
     * @param md
     * @param userKey
     * @param r
     * @param s
     * @param sm2Result
     */
    private fun sm2Verify(
        md: ByteArray,
        userKey: ECPoint,
        r: BigInteger,
        s: BigInteger,
        sm2Result: SM2Result
    ) {
        sm2Result.Res = null
        val e = BigInteger(1, md)
        val t = r.add(s).mod(ecc_n)
        if (t == BigInteger.ZERO) {
            return
        }
        var x1y1 = ecc_point_g.multiply(sm2Result.s)
        println("计算曲线点X0: " + x1y1.x.toBigInteger().toString(16))
        println("计算曲线点Y0: " + x1y1.y.toBigInteger().toString(16))
        println("")
        x1y1 = x1y1.add(userKey.multiply(t))
        println("计算曲线点X1: " + x1y1.x.toBigInteger().toString(16))
        println("计算曲线点Y1: " + x1y1.y.toBigInteger().toString(16))
        println("")
        sm2Result.Res = e.add(x1y1.x.toBigInteger()).mod(ecc_n)
        println("R: " + sm2Result.Res!!.toString(16))
    }

    /**
     * SM2验证签名
     * @param userId
     * @param publicKey
     * @param sourceData
     * @param signData
     * @return
     */
    fun sm2VerifySign(
        userId: ByteArray,
        publicKey: ByteArray?,
        sourceData: ByteArray?,
        signData: ByteArray?
    ): Boolean {
        if (publicKey == null || publicKey.isEmpty()) {
            return false
        }
        if (sourceData == null || sourceData.isEmpty()) {
            return false
        }
        val formatedPubKey: ByteArray
        if (publicKey.size == 64) {
            formatedPubKey = ByteArray(65)
            formatedPubKey[0] = 4
            System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.size)
        } else {
            formatedPubKey = publicKey
        }
        val userKey = ecc_curve.decodePoint(formatedPubKey)
        val z = sm2GetZ(userId, userKey)
        val sm3 = SM3Digest()
        sm3.update(z, 0, z.size)
        sm3.update(sourceData, 0, sourceData.size)
        val md = ByteArray(32)
        sm3.doFinal(md, 0)
        val bis = ByteArrayInputStream(signData)
        val dis = ASN1InputStream(bis)
        var sm2Result: SM2Result? = null
        try {

//            //bc-jdk16-146
//            DERObject derObj = dis.readObject();
//            Enumeration e = ((ASN1Sequence)derObj).getObjects();
//            BigInteger r = ((DERInteger)e.nextElement()).getValue();
//            BigInteger s = ((DERInteger)e.nextElement()).getValue();
//            sm2Result = new SM2Result();
//            sm2Result.r = r;
//            sm2Result.s = s;
//            sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
//            return sm2Result.r.equals(sm2Result.R);

            //bc-jdk15on-151
            val derObj = dis.readObject()
            val e = (derObj as ASN1Sequence).objects
            val r = (e.nextElement() as ASN1Integer).value
            val s = (e.nextElement() as ASN1Integer).value
            sm2Result = SM2Result()
            sm2Result.r = r
            sm2Result.s = s
            println("r: " + sm2Result.r!!.toString(16))
            println("s: " + sm2Result.s!!.toString(16))
            sm2Verify(md, userKey, sm2Result.r!!, sm2Result.s!!, sm2Result)
            return sm2Result.r == sm2Result.Res
        } catch (e1: Exception) {
            e1.printStackTrace()
        }
        return false
    }

    /**
     * SM2加密
     * @param publicKey
     * @param data
     * @param isC
     * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
     * @return
     */
    fun sm2Encrypt(publicKey: ByteArray?, data: ByteArray?, isC: Boolean, type: Int): ByteArray? {
//        Log.d(TAG, "sm2Encrypt() called with: publicKey = [" + FCharUtils.bytesToHexStr(publicKey) + "], data = [" + FCharUtils.bytesToHexStr(data) + "], isC = [" + isC + "], type = [" + type + "]");
        return if (publicKey != null && publicKey.size != 0) {
            if (data != null && data.size != 0) {
                val source = ByteArray(data.size)
                System.arraycopy(data, 0, source, 0, data.size)
                val formatedPubKey: ByteArray
                if (publicKey.size == 64) {
                    formatedPubKey = ByteArray(65)
                    formatedPubKey[0] = 4
                    System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.size)
                } else {
                    formatedPubKey = publicKey
                }
                val cipher = Cipher()
                val userKey = ecc_curve.decodePoint(formatedPubKey)
                val c1 = cipher.Init_enc(this, userKey)
                cipher.Encrypt(source)
                val c3 = ByteArray(32)
                cipher.Dofinal(c3)
                val x = DERInteger(c1.x.toBigInteger())
                val y = DERInteger(c1.y.toBigInteger())
                val derDig = DEROctetString(c3)
                val derEnc = DEROctetString(source)
                val v = ASN1EncodableVector()
                v.add(x)
                v.add(y)
                v.add(derDig)
                v.add(derEnc)
                val seq = DERSequence(v)
                val bos = ByteArrayOutputStream()
                val dos = DEROutputStream(bos)
                try {
                    dos.writeObject(seq)
                    val encRes = bos.toByteArray() //SM2加密结果
                    if (isC) {
                        dealSm2EncResultDel(encRes, type)
                    } else encRes
                } catch (var18: IOException) {
                    var18.printStackTrace()
                    null
                }
            } else {
                null
            }
        } else {
            null
        }
    }

    /**
     * SM2解密
     * @param privateKey
     * @param encryptedData
     * @param isC
     * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
     * @return
     */
    fun sm2Decrypt(
        privateKey: ByteArray?,
        encryptedData: ByteArray?,
        isC: Boolean,
        type: Int
    ): ByteArray? {
        var encryptedData = encryptedData
        return if (privateKey != null && privateKey.isNotEmpty()) {
            if (encryptedData != null && encryptedData.isNotEmpty()) {
                if (isC) {
                    encryptedData = dealSm2EncResultAdd(encryptedData, type)
                }
                var enc = ByteArray(encryptedData!!.size)
                System.arraycopy(encryptedData, 0, enc, 0, encryptedData.size)
                val sm2 = instance
                val userD = BigInteger(1, privateKey)
                val bis = ByteArrayInputStream(enc)
                val dis = ASN1InputStream(bis)
                try {
                    //bc-jdk16-146
//                    DERObject derObj = dis.readObject();
//                    ASN1Sequence asn1 = (ASN1Sequence)derObj;
//                    DERInteger x = (DERInteger)asn1.getObjectAt(0);
//                    DERInteger y = (DERInteger)asn1.getObjectAt(1);
//                    ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);
//                    Cipher cipher = new Cipher();
//                    cipher.Init_dec(userD, c1);
//                    DEROctetString data = (DEROctetString)asn1.getObjectAt(3);

                    //bc-jdk15on-151
                    val derObj = dis.readObject()
                    val e = (derObj as ASN1Sequence).objects
                    val r = (e.nextElement() as ASN1Integer).value
                    val s = (e.nextElement() as ASN1Integer).value
                    val c1 = sm2.ecc_curve.createPoint(r, s)
                    val cipher = Cipher()
                    cipher.Init_dec(userD, c1)
                    e.nextElement() //此项为C3不需要,解密需要用后面一项C2
                    val data = e.nextElement() as DEROctetString
                    enc = data.octets
                    cipher.Decrypt(enc)
                    val c3 = ByteArray(32)
                    cipher.Dofinal(c3)
                    enc
                } catch (var15: IOException) {
                    var15.printStackTrace()
                    null
                }
            } else {
                null
            }
        } else {
            null
        }
    }

    /**
     * 处理SM2签名结果为C1C2拼接样式
     * @param res
     * @return
     */
    fun dealSm2SignResultC(res: ByteArray?): ByteArray? {
        if (res == null) {
            return null
        }
        var s1 = ""
        var s2 = ""
        var resHex = bytesToHexStr(res)
        if (resHex!!.startsWith("30")) {
            resHex = resHex.substring(4)
            //解析C1 X部分
            if (resHex.startsWith("0220")) {
                s1 = resHex.substring(4, 68)
                resHex = resHex.substring(68)
            } else if (resHex.startsWith("022100")) {
                s1 = resHex.substring(6, 70)
                resHex = resHex.substring(70)
            } else if (resHex.startsWith("02")) {
                var s1Len = resHex.substring(2, 4).toInt(16)
                s1 = resHex.substring(4, 4 + s1Len * 2)
                resHex = resHex.substring(4 + s1Len * 2)
                while (s1Len < 0x20) {
                    s1 = "00$s1"
                    s1Len = s1.length
                }
            } else {
                return null
            }
            //解析C1 Y部分
            if (resHex.startsWith("0220")) {
                s2 = resHex.substring(4, 68)
            } else if (resHex.startsWith("022100")) {
                s2 = resHex.substring(6, 70)
            } else if (resHex.startsWith("02")) {
                var s2Len = resHex.substring(2, 4).toInt(16)
                s2 = resHex.substring(4, 4 + s2Len * 2)
                while (s2Len < 0x20) {
                    s2 = "00$s2"
                    s2Len = s2.length
                }
            } else {
                return null
            }
            resHex = s1 + s2
            return hexString2ByteArray(resHex)
        }
        return null
    }

    /**
     * 处理SM2签名结果，补位为java可解析的格式
     * @param res
     * @return
     */
    fun dealSm2SignResultAdd(res: ByteArray?): ByteArray? {
        if (res == null || res.size != 64) {
            return null
        }
        val smR = ByteArray(32)
        val smS = ByteArray(32)
        System.arraycopy(res, 0, smR, 0, 32)
        System.arraycopy(res, 32, smS, 0, 32)
        var smRStr = bytesToHexStr(smR)
        var smSStr = bytesToHexStr(smS)
        while (smRStr!!.startsWith("00")) {
            smRStr = smRStr.substring(2)
        }
        val smRStrLen = smRStr.length / 2
        var tc = 0
        tc = smRStr[0].toInt()
        smRStr = if (tc > '7'.toInt()) {
            "02" + int2HexStr(smRStrLen + 1) + "00" + smRStr
        } else {
            "02" + int2HexStr(smRStrLen) + smRStr
        }
        while (smSStr!!.startsWith("00")) {
            smSStr = smSStr.substring(2)
        }
        val smSStrLen = smSStr.length / 2
        tc = smSStr[0].toInt()
        smSStr = if (tc > '7'.toInt()) {
            "02" + int2HexStr(smSStrLen + 1) + "00" + smSStr
        } else {
            "02" + int2HexStr(smSStrLen) + smSStr
        }
        var ret = smRStr + smSStr
        val allLenght = ret.length / 2
        ret = "30" + intToByte(allLenght) + ret
        return hexString2ByteArray(ret)
    }

    companion object {
        private const val TAG = "SM2"
        var ecc_param = arrayOf(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        )
        val instance: SM2
            get() = SM2()

        /**
         * 处理SM2加密结果为3081格式
         * @param res
         * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
         * @return
         */
        fun dealSm2EncResultAdd(res: ByteArray?, type: Int): ByteArray? {
            if (res == null) {
                return null
            }
            if (res.size < 97) {
                return null
            }
            if (type == 3 && (res[0].toInt() != 4)) {
                return null
            }
            var resStr = bytesToHexStr(res)
            if (type == 3) {
                resStr = resStr!!.substring(2)
            }
            var c1x = resStr!!.substring(0, 64)
            var c1y = resStr.substring(64, 128)
            var c3 = resStr.substring(128, 192)
            var c2 = resStr.substring(192)
            if (type == 1 || type == 3) {
                c2 = resStr.substring(128, resStr.length - 64)
                c3 = resStr.substring(resStr.length - 64)
            }

            //处理C2
            while (c2.startsWith("00")) {
                c2 = c2.substring(2)
            }
            val c2Len = c2.length / 2
            var c2StartStr = "04"
            if (c2Len >= 0x80) {
                c2StartStr += "81"
            }
            c2 = c2StartStr + int2HexStr(c2Len) + c2
            //处理C3
            while (c3.startsWith("00")) {
                c3 = c3.substring(2)
            }
            val c3Len = c3.length / 2
            c3 = "04" + int2HexStr(c3Len) + c3
            //处理C1Y
            while (c1y.startsWith("00")) {
                c1y = c1y.substring(2)
            }
            val c1yLen = c1y.length / 2
            var tc = c1y[0]
            c1y = if (tc > '7') {
                "02" + int2HexStr(c1yLen + 1) + "00" + c1y
            } else {
                "02" + int2HexStr(c1yLen) + c1y
            }
            //处理C1X
            while (c1x.startsWith("00")) {
                c1x = c1x.substring(2)
            }
            val c1xLen = c1x.length / 2
            tc = c1x[0]
            c1x = if (tc > '7') {
                "02" + int2HexStr(c1xLen + 1) + "00" + c1x
            } else {
                "02" + int2HexStr(c1xLen) + c1x
            }
            var dealStr = c1x + c1y + c3 + c2
            val dealDataLen = dealStr.length / 2
            val lenStr = int2HexStr(dealDataLen)
            dealStr = "30" + int2HexStr(0x80 + lenStr.length / 2) + lenStr + dealStr
            return hexString2ByteArray(dealStr)
        }

        /**
         * 处理SM2加密结果为C1C2C3拼接样式
         * @param res
         * @param type 1--C1C2C3, 2--C1C3C2, 3--"04"+C1C2C3
         * @return
         */
        fun dealSm2EncResultDel(res: ByteArray?, type: Int): ByteArray? {
//        Log.d(TAG, "dealSm2EncResultDel() called with: res = [" + FCharUtils.bytesToHexStr(res) + "], type = [" + type + "]");
            if (res == null) {
                return null
            }
            var c1x: String
            var c1y: String
            val c2: String
            var c3: String
            var resHex = bytesToHexStr(res)
            if (resHex!!.startsWith("30")) {
                resHex = resHex.substring(2)
                var tl = resHex.substring(0, 2)
                var bl = hexString2ByteArray(tl)
                var bt: Int = bl!![0].toInt() and 0xFF
                var l = 0
                if (bt > 0x80) {
                    l = bt - 0x80
                }
                resHex = resHex.substring((l + 1) * 2)
                //解析C1 X部分
                when {
                    resHex.startsWith("0220") -> {
                        c1x = resHex.substring(4, 68)
                        resHex = resHex.substring(68)
                    }
                    resHex.startsWith("022100") -> {
                        c1x = resHex.substring(6, 70)
                        resHex = resHex.substring(70)
                    }
                    resHex.startsWith("02") -> {
                        var c1xLen = resHex.substring(2, 4).toInt(16)
                        c1x = resHex.substring(4, 4 + c1xLen * 2)
                        resHex = resHex.substring(4 + c1xLen * 2)
                        while (c1xLen < 0x20) {
                            c1x = "00$c1x"
                            c1xLen = c1x.length / 2
                        }
                    }
                    else -> return null
                }
                //解析C1 Y部分
                when {
                    resHex.startsWith("0220") -> {
                        c1y = resHex.substring(4, 68)
                        resHex = resHex.substring(68)
                    }
                    resHex.startsWith("022100") -> {
                        c1y = resHex.substring(6, 70)
                        resHex = resHex.substring(70)
                    }
                    resHex.startsWith("02") -> {
                        var c1yLen = resHex.substring(2, 4).toInt(16)
                        c1y = resHex.substring(4, 4 + c1yLen * 2)
                        resHex = resHex.substring(4 + c1yLen * 2)
                        while (c1yLen < 0x20) {
                            c1y = "00$c1y"
                            c1yLen = c1y.length / 2
                        }
                    }
                    else -> return null
                }
                //解析C3
                when {
                    resHex.startsWith("0420") -> {
                        c3 = resHex.substring(4, 68)
                        resHex = resHex.substring(68)
                    }
                    resHex.startsWith("042100") -> {
                        c3 = resHex.substring(6, 70)
                        resHex = resHex.substring(70)
                    }
                    resHex.startsWith("04") -> {
                        var c3Len = resHex.substring(2, 4).toInt(16)
                        c3 = resHex.substring(4, 4 + c3Len * 2)
                        resHex = resHex.substring(4 + c3Len * 2)
                        while (c3Len < 0x20) {
                            c3 = "00$c3"
                            c3Len = c3.length / 2
                        }
                    }
                    else -> return null
                }
                //解析C2
                if (resHex.startsWith("04")) {
                    resHex = resHex.substring(2)
                    if (resHex.length < 2) {
                        return null
                    }
                    tl = resHex.substring(0, 2)
                    bl = hexString2ByteArray(tl)
                    bt = bl!![0].toInt() and 0xFF
                    l = 0
                    if (bt > 0x80) {
                        l = bt - 0x80
                    }
                    c2 = resHex.substring((l + 1) * 2)
                } else {
                    return null
                }
                resHex = when (type) {
                    1 -> c1x + c1y + c2 + c3
                    2 -> c1x + c1y + c3 + c2
                    else -> "04$c1x$c1y$c2$c3"
                }
                return hexString2ByteArray(resHex)
            }
            return null
        }
    }

    init {
        ecc_p = BigInteger(ecc_param[0], 16)
        ecc_a = BigInteger(ecc_param[1], 16)
        ecc_b = BigInteger(ecc_param[2], 16)
        ecc_n = BigInteger(ecc_param[3], 16)
        ecc_gx = BigInteger(ecc_param[4], 16)
        ecc_gy = BigInteger(ecc_param[5], 16)
        ecc_gx_fieldelement = ECFieldElement.Fp(ecc_p, ecc_gx)
        ecc_gy_fieldelement = ECFieldElement.Fp(ecc_p, ecc_gy)
        ecc_curve = ECCurve.Fp(ecc_p, ecc_a, ecc_b)
        ecc_point_g = ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement)
        ecc_bc_spec = ECDomainParameters(ecc_curve, ecc_point_g, ecc_n)
        val ecc_ecgenparam = ECKeyGenerationParameters(ecc_bc_spec, SecureRandom())
        ecc_key_pair_generator = ECKeyPairGenerator()
        ecc_key_pair_generator.init(ecc_ecgenparam)
    }
}