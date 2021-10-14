package com.froad.sm2testpro.utils

import com.froad.sm2testpro.utils.FCharUtils.byteToInt
import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray
import com.froad.sm2testpro.utils.FCharUtils.intToBytes
import com.froad.sm2testpro.utils.FCharUtils.longToBytes

/**
 * Created by FW on 2017/4/20.
 */
object SM3 {
    @JvmField
    val iv = byteArrayOf(
        115, -128, 22, 111, 73,
        20, -78, -71, 23, 36, 66, -41,
        -38, -118, 6, 0, -87, 111, 48,
        -68, 22, 49, 56, -86, -29,
        -115, -18, 77, -80, -5, 14,
        78
    )
    var Tj = IntArray(64)
    fun CF(V: ByteArray, B: ByteArray): ByteArray {
        val v = convert(V)
        val b = convert(B)
        return convert(CF(v, b))
    }

    private fun convert(arr: ByteArray): IntArray {
        val out = IntArray(arr.size / 4)
        val tmp = ByteArray(4)
        var i = 0
        while (i < arr.size) {
            System.arraycopy(arr, i, tmp, 0, 4)
            out[i / 4] = bigEndianByteToInt(tmp)
            i += 4
        }
        return out
    }

    private fun convert(arr: IntArray): ByteArray {
        val out = ByteArray(arr.size * 4)
        var tmp: ByteArray? = null
        for (i in arr.indices) {
            tmp = bigEndianIntToByte(arr[i])
            System.arraycopy(tmp, 0, out, i * 4, 4)
        }
        return out
    }

    fun CF(V: IntArray, B: IntArray): IntArray {
        var a = V[0]
        var b = V[1]
        var c = V[2]
        var d = V[3]
        var e = V[4]
        var f = V[5]
        var g = V[6]
        var h = V[7]
        val arr = expand(B)
        val w = arr[0]
        val w1 = arr[1]
        for (j in 0..63) {
            var ss1 = bitCycleLeft(a, 12) + e + bitCycleLeft(
                Tj[j], j
            )
            ss1 = bitCycleLeft(ss1, 7)
            val ss2 = ss1 xor bitCycleLeft(a, 12)
            val tt1 = FFj(a, b, c, j) + d + ss2 + w1[j]
            val tt2 = GGj(e, f, g, j) + h + ss1 + w[j]
            d = c
            c = bitCycleLeft(b, 9)
            b = a
            a = tt1
            h = g
            g = bitCycleLeft(f, 19)
            f = e
            e = P0(tt2)
        }
        val out = IntArray(8)
        out[0] = a xor V[0]
        out[1] = b xor V[1]
        out[2] = c xor V[2]
        out[3] = d xor V[3]
        out[4] = e xor V[4]
        out[5] = f xor V[5]
        out[6] = g xor V[6]
        out[7] = h xor V[7]
        return out
    }

    private fun expand(B: IntArray): Array<IntArray> {
        val W = IntArray(68)
        val W1 = IntArray(64)
        for (i in B.indices) {
            W[i] = B[i]
        }
        for (i in 16..67) {
            W[i] = P1(
                W[i - 16] xor W[i - 9] xor bitCycleLeft(
                    W[i - 3],
                    15
                )
            ) xor
                    bitCycleLeft(
                        W[i - 13],
                        7
                    ) xor W[i - 6]
        }
        for (i in 0..63) {
            W1[i] = W[i] xor W[i + 4]
        }
        return arrayOf(W, W1)
    }

    private fun bigEndianIntToByte(num: Int): ByteArray {
        return back(intToBytes(num))
    }

    private fun bigEndianByteToInt(bytes: ByteArray): Int {
        return byteToInt(back(bytes))
    }

    private fun FFj(X: Int, Y: Int, Z: Int, j: Int): Int {
        return if (j in 0..15) {
            FF1j(X, Y, Z)
        } else FF2j(X, Y, Z)
    }

    private fun GGj(X: Int, Y: Int, Z: Int, j: Int): Int {
        return if (j in 0..15) {
            GG1j(X, Y, Z)
        } else GG2j(X, Y, Z)
    }

    private fun FF1j(X: Int, Y: Int, Z: Int): Int {
        return X xor Y xor Z
    }

    private fun FF2j(X: Int, Y: Int, Z: Int): Int {
        return X and Y or (X and Z) or (Y and Z)
    }

    private fun GG1j(X: Int, Y: Int, Z: Int): Int {
        return X xor Y xor Z
    }

    private fun GG2j(X: Int, Y: Int, Z: Int): Int {
        return X and Y or (X xor -0x1) and Z
    }

    private fun P0(X: Int): Int {
        var y = rotateLeft(X, 9)
        y = bitCycleLeft(X, 9)
        var z = rotateLeft(X, 17)
        z = bitCycleLeft(X, 17)
        return X xor y xor z
    }

    private fun P1(X: Int): Int {
        return X xor bitCycleLeft(X, 15) xor bitCycleLeft(X, 23)
    }

    @JvmStatic
    fun padding(`in`: ByteArray, bLen: Int): ByteArray {
        var k = 448 - (8 * `in`.size + 1) % 512
        if (k < 0) {
            k = 960 - (8 * `in`.size + 1) % 512
        }
        ++k
        val padd = ByteArray(k / 8)
        padd[0] = -128
        val n = (`in`.size * 8 + bLen * 512).toLong()
        val out = ByteArray(`in`.size + k / 8 + 8)
        var pos = 0
        System.arraycopy(`in`, 0, out, 0, `in`.size)
        pos += `in`.size
        System.arraycopy(padd, 0, out, pos, padd.size)
        pos += padd.size
        val tmp = back(longToBytes(n))
        System.arraycopy(tmp, 0, out, pos, tmp.size)
        return out
    }

    private fun back(`in`: ByteArray): ByteArray {
        val out = ByteArray(`in`.size)
        for (i in out.indices) {
            out[i] = `in`[out.size - i - 1]
        }
        return out
    }

    fun rotateLeft(x: Int, n: Int): Int {
        return (x shl n) or (x shr 32 - n)
    }

    private fun bitCycleLeft(n: Int, bitLen: Int): Int {
        var bitLen = bitLen
        bitLen %= 32
        var tmp = bigEndianIntToByte(n)
        val byteLen = bitLen / 8
        val len = bitLen % 8
        if (byteLen > 0) {
            tmp = byteCycleLeft(tmp, byteLen)
        }
        if (len > 0) {
            tmp = bitSmall8CycleLeft(tmp, len)
        }
        return bigEndianByteToInt(tmp)
    }

    private fun bitSmall8CycleLeft(inBytes: ByteArray, len: Int): ByteArray {
        val tmp = ByteArray(inBytes.size)
        for (i in tmp.indices) {
            val t1: Int = ((inBytes[i].toInt() and 0xFF) shl len)
            val t2: Int = ((inBytes[(i + 1) % tmp.size].toInt() and 0xFF) shr (8 - len))
            val t3: Int = (t1 or t2)
            tmp[i] = t3.toByte()
        }
        return tmp
    }

    private fun byteCycleLeft(`in`: ByteArray, byteLen: Int): ByteArray {
        val tmp = ByteArray(`in`.size)
        System.arraycopy(`in`, byteLen, tmp, 0, `in`.size - byteLen)
        System.arraycopy(`in`, 0, tmp, `in`.size - byteLen, byteLen)
        return tmp
    }

    fun sm3Hash(scrData: String?): String? {
        val md = ByteArray(32)
        val msg1 = hexString2ByteArray(scrData!!)
        val sm3 = SM3Digest()
        sm3.update(msg1, 0, msg1!!.size)
        sm3.doFinal(md, 0)
        return bytesToHexStr(md)
    }

    init {
        for (i in 0..15) {
            Tj[i] = 2043430169
        }
        for (i in 16..63) {
            Tj[i] = 2055708042
        }
    }
}