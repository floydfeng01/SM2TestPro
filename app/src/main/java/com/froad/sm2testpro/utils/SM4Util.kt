package com.froad.sm2testpro.utils

import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.FCharUtils.hexStr2LV_2
import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray
import java.util.*

/**
 * Created by FW on 2018/5/15.
 */
class SM4Util {
    private val Sbox = byteArrayOf(
        0xd6.toByte(),
        0x90.toByte(),
        0xe9.toByte(),
        0xfe.toByte(),
        0xcc.toByte(),
        0xe1.toByte(),
        0x3d,
        0xb7.toByte(),
        0x16,
        0xb6.toByte(),
        0x14,
        0xc2.toByte(),
        0x28,
        0xfb.toByte(),
        0x2c,
        0x05,
        0x2b,
        0x67,
        0x9a.toByte(),
        0x76,
        0x2a,
        0xbe.toByte(),
        0x04,
        0xc3.toByte(),
        0xaa.toByte(),
        0x44,
        0x13,
        0x26,
        0x49,
        0x86.toByte(),
        0x06,
        0x99.toByte(),
        0x9c.toByte(),
        0x42,
        0x50,
        0xf4.toByte(),
        0x91.toByte(),
        0xef.toByte(),
        0x98.toByte(),
        0x7a,
        0x33,
        0x54,
        0x0b,
        0x43,
        0xed.toByte(),
        0xcf.toByte(),
        0xac.toByte(),
        0x62,
        0xe4.toByte(),
        0xb3.toByte(),
        0x1c,
        0xa9.toByte(),
        0xc9.toByte(),
        0x08,
        0xe8.toByte(),
        0x95.toByte(),
        0x80.toByte(),
        0xdf.toByte(),
        0x94.toByte(),
        0xfa.toByte(),
        0x75,
        0x8f.toByte(),
        0x3f,
        0xa6.toByte(),
        0x47,
        0x07,
        0xa7.toByte(),
        0xfc.toByte(),
        0xf3.toByte(),
        0x73,
        0x17,
        0xba.toByte(),
        0x83.toByte(),
        0x59,
        0x3c,
        0x19,
        0xe6.toByte(),
        0x85.toByte(),
        0x4f,
        0xa8.toByte(),
        0x68,
        0x6b,
        0x81.toByte(),
        0xb2.toByte(),
        0x71,
        0x64,
        0xda.toByte(),
        0x8b.toByte(),
        0xf8.toByte(),
        0xeb.toByte(),
        0x0f,
        0x4b,
        0x70,
        0x56,
        0x9d.toByte(),
        0x35,
        0x1e,
        0x24,
        0x0e,
        0x5e,
        0x63,
        0x58,
        0xd1.toByte(),
        0xa2.toByte(),
        0x25,
        0x22,
        0x7c,
        0x3b,
        0x01,
        0x21,
        0x78,
        0x87.toByte(),
        0xd4.toByte(),
        0x00,
        0x46,
        0x57,
        0x9f.toByte(),
        0xd3.toByte(),
        0x27,
        0x52,
        0x4c,
        0x36,
        0x02,
        0xe7.toByte(),
        0xa0.toByte(),
        0xc4.toByte(),
        0xc8.toByte(),
        0x9e.toByte(),
        0xea.toByte(),
        0xbf.toByte(),
        0x8a.toByte(),
        0xd2.toByte(),
        0x40,
        0xc7.toByte(),
        0x38,
        0xb5.toByte(),
        0xa3.toByte(),
        0xf7.toByte(),
        0xf2.toByte(),
        0xce.toByte(),
        0xf9.toByte(),
        0x61,
        0x15,
        0xa1.toByte(),
        0xe0.toByte(),
        0xae.toByte(),
        0x5d,
        0xa4.toByte(),
        0x9b.toByte(),
        0x34,
        0x1a,
        0x55,
        0xad.toByte(),
        0x93.toByte(),
        0x32,
        0x30,
        0xf5.toByte(),
        0x8c.toByte(),
        0xb1.toByte(),
        0xe3.toByte(),
        0x1d,
        0xf6.toByte(),
        0xe2.toByte(),
        0x2e,
        0x82.toByte(),
        0x66,
        0xca.toByte(),
        0x60,
        0xc0.toByte(),
        0x29,
        0x23,
        0xab.toByte(),
        0x0d,
        0x53,
        0x4e,
        0x6f,
        0xd5.toByte(),
        0xdb.toByte(),
        0x37,
        0x45,
        0xde.toByte(),
        0xfd.toByte(),
        0x8e.toByte(),
        0x2f,
        0x03,
        0xff.toByte(),
        0x6a,
        0x72,
        0x6d,
        0x6c,
        0x5b,
        0x51,
        0x8d.toByte(),
        0x1b,
        0xaf.toByte(),
        0x92.toByte(),
        0xbb.toByte(),
        0xdd.toByte(),
        0xbc.toByte(),
        0x7f,
        0x11,
        0xd9.toByte(),
        0x5c,
        0x41,
        0x1f,
        0x10,
        0x5a,
        0xd8.toByte(),
        0x0a,
        0xc1.toByte(),
        0x31,
        0x88.toByte(),
        0xa5.toByte(),
        0xcd.toByte(),
        0x7b,
        0xbd.toByte(),
        0x2d,
        0x74,
        0xd0.toByte(),
        0x12,
        0xb8.toByte(),
        0xe5.toByte(),
        0xb4.toByte(),
        0xb0.toByte(),
        0x89.toByte(),
        0x69,
        0x97.toByte(),
        0x4a,
        0x0c,
        0x96.toByte(),
        0x77,
        0x7e,
        0x65,
        0xb9.toByte(),
        0xf1.toByte(),
        0x09,
        0xc5.toByte(),
        0x6e,
        0xc6.toByte(),
        0x84.toByte(),
        0x18,
        0xf0.toByte(),
        0x7d,
        0xec.toByte(),
        0x3a,
        0xdc.toByte(),
        0x4d,
        0x20,
        0x79,
        0xee.toByte(),
        0x5f,
        0x3e,
        0xd7.toByte(),
        0xcb.toByte(),
        0x39,
        0x48
    )
    private val CK = intArrayOf(
        0x00070e15,
        0x1c232a31,
        0x383f464d,
        0x545b6269,
        0x70777e85,
        -0x736c655f,
        -0x57504943,
        -0x3b342d27,
        -0x1f18110b,
        -0x3fcf5ef,
        0x181f262d,
        0x343b4249,
        0x50575e65,
        0x6c737a81,
        -0x77706963,
        -0x5b544d47,
        -0x3f38312b,
        -0x231c150f,
        -0x700f9f3,
        0x141b2229,
        0x30373e45,
        0x4c535a61,
        0x686f767d,
        -0x7b746d67,
        -0x5f58514b,
        -0x433c352f,
        -0x27201913,
        -0xb04fdf7,
        0x10171e25,
        0x2c333a41,
        0x484f565d,
        0x646b7279
    )

    private fun Rotl(x: Int, y: Int): Int {
        return x shl y or x ushr 32 - y
    }

    private fun ByteSub(A: Int): Int {
        return Sbox[A ushr 24 and 0xFF].toInt() and 0xFF shl 24 or (Sbox[A ushr 16 and 0xFF].toInt() and 0xFF shl 16) or (Sbox[A ushr 8 and 0xFF].toInt() and 0xFF shl 8) or (Sbox[A and 0xFF].toInt() and 0xFF)
    }

    private fun L1(B: Int): Int {
        return B xor Rotl(B, 2) xor Rotl(B, 10) xor Rotl(B, 18) xor Rotl(B, 24)
    }

    private fun L2(B: Int): Int {
        return B xor Rotl(B, 13) xor Rotl(B, 23)
        // return B^(B<<13|B>>>19)^(B<<23|B>>>9);
    }

    fun SMS4Crypt(Input: ByteArray, Output: ByteArray, rk: IntArray) {
        var r: Int
        var mid: Int
        var x0: Int
        var x1: Int
        var x2: Int
        var x3: Int
        val x = IntArray(4)
        val tmp = IntArray(4)
        for (i in 0..3) {
            tmp[0] = Input[0 + 4 * i].toInt() and 0xff
            tmp[1] = Input[1 + 4 * i].toInt() and 0xff
            tmp[2] = Input[2 + 4 * i].toInt() and 0xff
            tmp[3] = Input[3 + 4 * i].toInt() and 0xff
            x[i] = tmp[0] shl 24 or (tmp[1] shl 16) or (tmp[2] shl 8) or tmp[3]
            // x[i]=(Input[0+4*i]<<24|Input[1+4*i]<<16|Input[2+4*i]<<8|Input[3+4*i]);
        }
        r = 0
        while (r < 32) {
            mid = x[1] xor x[2] xor x[3] xor rk[r + 0]
            mid = ByteSub(mid)
            x[0] = x[0] xor L1(mid) // x4
            mid = x[2] xor x[3] xor x[0] xor rk[r + 1]
            mid = ByteSub(mid)
            x[1] = x[1] xor L1(mid) // x5
            mid = x[3] xor x[0] xor x[1] xor rk[r + 2]
            mid = ByteSub(mid)
            x[2] = x[2] xor L1(mid) // x6
            mid = x[0] xor x[1] xor x[2] xor rk[r + 3]
            mid = ByteSub(mid)
            x[3] = x[3] xor L1(mid) // x7
            r += 4
        }

        // Reverse
        var j = 0
        while (j < 16) {
            Output[j] = (x[3 - j / 4] ushr 24 and 0xFF).toByte()
            Output[j + 1] = (x[3 - j / 4] ushr 16 and 0xFF).toByte()
            Output[j + 2] = (x[3 - j / 4] ushr 8 and 0xFF).toByte()
            Output[j + 3] = (x[3 - j / 4] and 0xFF).toByte()
            j += 4
        }
    }

    private fun SMS4KeyExt(Key: ByteArray?, rk: IntArray, CryptFlag: Int) {
        var r: Int
        var mid: Int
        val x = IntArray(4)
        val tmp = IntArray(4)
        for (i in 0..3) {
            tmp[0] = Key!![0 + 4 * i].toInt() and 0xFF
            tmp[1] = Key[1 + 4 * i].toInt() and 0xff
            tmp[2] = Key[2 + 4 * i].toInt() and 0xff
            tmp[3] = Key[3 + 4 * i].toInt() and 0xff
            x[i] = tmp[0] shl 24 or (tmp[1] shl 16) or (tmp[2] shl 8) or tmp[3]
            // x[i]=Key[0+4*i]<<24|Key[1+4*i]<<16|Key[2+4*i]<<8|Key[3+4*i];
        }
        x[0] = x[0] xor -0x5c4e453a
        x[1] = x[1] xor 0x56aa3350
        x[2] = x[2] xor 0x677d9197
        x[3] = x[3] xor -0x4d8fdd24
        r = 0
        while (r < 32) {
            mid = x[1] xor x[2] xor x[3] xor CK[r + 0]
            mid = ByteSub(mid)
            x[0] = x[0] xor L2(mid)
            rk[r + 0] = x[0] // rk0=K4
            mid = x[2] xor x[3] xor x[0] xor CK[r + 1]
            mid = ByteSub(mid)
            x[1] = x[1] xor L2(mid)
            rk[r + 1] = x[1] // rk1=K5
            mid = x[3] xor x[0] xor x[1] xor CK[r + 2]
            mid = ByteSub(mid)
            x[2] = x[2] xor L2(mid)
            rk[r + 2] = x[2] // rk2=K6
            mid = x[0] xor x[1] xor x[2] xor CK[r + 3]
            mid = ByteSub(mid)
            x[3] = x[3] xor L2(mid)
            rk[r + 3] = x[3] // rk3=K7
            r += 4
        }

        if (CryptFlag == DECRYPT) {
            r = 0
            while (r < 16) {
                mid = rk[r]
                rk[r] = rk[31 - r]
                rk[31 - r] = mid
                r++
            }
        }
    }

    /**
     * sm4 ECB加密
     * @param in
     * @param key
     * @param CryptFlag
     * @param isMustAdd
     * @param type 0--不需要补长度，1--数据前需要补两字节长度
     * @return
     */
    fun sms4_ecb(
        `in`: ByteArray?,
        key: ByteArray?,
        CryptFlag: Int,
        isMustAdd: Boolean,
        type: Int
    ): ByteArray {
        var key = key
        var point = 0
        val round_key = IntArray(ROUND)
        key = dealSm4Key(key)
        SMS4KeyExt(key, round_key, CryptFlag)
        val input: ByteArray?
        if (CryptFlag == ENCRYPT) {
            var inStr = bytesToHexStr(`in`)
            if (type == 1) {
                inStr = hexStr2LV_2(inStr)
            }
            input = dealSm4Data(hexString2ByteArray(inStr!!), isMustAdd)
        } else {
            input = dealSm4Data(`in`, false)
        }
        var inputLen = input!!.size
        val output = ByteArray(inputLen)
        var tempInput: ByteArray
        val tempOutput = ByteArray(16)
        while (inputLen >= BLOCK) {
            tempInput = Arrays.copyOfRange(input, point, point + 16)
            SMS4Crypt(tempInput, tempOutput, round_key)
            System.arraycopy(tempOutput, 0, output, point, BLOCK)
            inputLen -= BLOCK
            point += BLOCK
        }
        if (CryptFlag == DECRYPT) { //解密
            if (type == 1) {
                val dataLen: Int = (output[0].toInt() shl 8) + output[1]
                println("sms4_ecb>>>dataLen:$dataLen")
                val tempOut = ByteArray(dataLen)
                System.arraycopy(output, 2, tempOut, 0, dataLen)
                return tempOut
            }
        }
        return output
    }

    fun xors(iv: ByteArray, `in`: ByteArray) {
        for (i in `in`.indices) {
            `in`[i] = (`in`[i].toInt() xor iv[i].toInt()).toByte()
        }
    }

    fun sms4_cbc(
        iv: ByteArray?,
        `in`: ByteArray?,
        key: ByteArray?,
        CryptFlag: Int,
        isMustAdd: Boolean
    ): ByteArray {
        var point = 0
        val round_key = IntArray(ROUND)
        SMS4KeyExt(key, round_key, CryptFlag)
        val input = dealSm4Data(`in`, isMustAdd)
        var inputLen = input!!.size
        val output = ByteArray(inputLen)
        val tmpIV = ByteArray(16)
        var tmpInput: ByteArray
        val tempOutput = ByteArray(16)
        if (CryptFlag == ENCRYPT) {
            System.arraycopy(iv, 0, tmpIV, 0, 16)
            while (inputLen >= BLOCK) {
                tmpInput = Arrays.copyOfRange(input, point, point + 16)
                xors(tmpIV, tmpInput)
                SMS4Crypt(tmpInput, tempOutput, round_key)
                System.arraycopy(tempOutput, 0, tmpIV, 0, 16)
                System.arraycopy(tempOutput, 0, output, point, BLOCK)
                inputLen -= BLOCK
                point += BLOCK
            }
        } else {
            System.arraycopy(iv, 0, tmpIV, 0, 16)
            while (inputLen >= BLOCK) {
                tmpInput = Arrays.copyOfRange(input, point, point + 16)
                SMS4Crypt(tmpInput, tempOutput, round_key)
                xors(tmpIV, tempOutput)
                System.arraycopy(tmpInput, 0, tmpIV, 0, 16)
                System.arraycopy(tempOutput, 0, output, point, BLOCK)
                inputLen -= BLOCK
                point += BLOCK
            }
        }
        return output
    }

    fun dealMac(data: ByteArray?, encKeyBytes: ByteArray?): ByteArray {
        val iv = ByteArray(16)
        val output = sms4_cbc(iv, data, encKeyBytes, ENCRYPT, false)
        val mac = ByteArray(16)
        System.arraycopy(output, output.size - 16, mac, 0, 16)
        return mac
    }

    companion object {
        private const val TAG = "SM4"
        private var sm4: SM4Util? = null
        const val ENCRYPT = 1
        const val DECRYPT = 0
        const val ROUND = 32
        private const val BLOCK = 16
        const val ENCRK = "510B326E1BB9ECDEB8B2E331B04731AF"
        val instance: SM4Util = SingleHolder.sM4Util

        private fun dealSm4Key(key: ByteArray?): ByteArray? {
            if (key == null) {
                return null
            }
            val keyLen = key.size
            val dealKey = ByteArray(16)
            if (keyLen >= 16) {
                System.arraycopy(key, 0, dealKey, 0, 16)
            } else if (keyLen < 16) {
                System.arraycopy(key, 0, dealKey, 0, keyLen)
            }
            return dealKey
        }

        /**
         * 处理SM4加密数据，16字节整数倍，强补80，长度不足16字节的后再部00
         * @param data
         * @param isMustAdd 是否需要强补80
         * @return
         */
        private fun dealSm4Data(data: ByteArray?, isMustAdd: Boolean): ByteArray? {
            if (data == null) {
                return null
            }
            var dataHexStr = bytesToHexStr(data)
            if (isMustAdd) {
                dataHexStr += "80"
            }
            val dataLen = dataHexStr!!.length / 2
            var tl = dataLen / 16
            var needAppend = false //是否需要补位80
            if (dataLen % 16 != 0) {
                tl++
                needAppend = true
            }
            val dealData = ByteArray(tl * 16)
            System.arraycopy(hexString2ByteArray(dataHexStr), 0, dealData, 0, dataLen)
            if (!isMustAdd && needAppend) {
                dealData[dataLen] = 0x80.toByte()
            }
            println("dealSm4Data>>>dealData:${bytesToHexStr(dealData)}")
            return dealData
        }
    }

    object SingleHolder {
        var sM4Util = SM4Util()
    }
}