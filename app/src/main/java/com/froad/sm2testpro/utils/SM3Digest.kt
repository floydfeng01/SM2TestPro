package com.froad.sm2testpro.utils

import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.SM3.CF
import com.froad.sm2testpro.utils.SM3.padding

/**
 * Created by FW on 2017/7/5.
 */
class SM3Digest {
    private val xBuf = ByteArray(64)
    private var xBufOff = 0
    private var V = SM3.iv.clone()
    private var cntBlock = 0

    constructor() {}
    constructor(t: SM3Digest) {
        System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.size)
        xBufOff = t.xBufOff
        System.arraycopy(t.V, 0, V, 0, t.V.size)
    }

    fun doFinal(out: ByteArray?, outOff: Int): Int {
        val tmp = doFinal()
        System.arraycopy(tmp, 0, out, 0, tmp.size)
        return 32
    }

    fun reset() {
        xBufOff = 0
        cntBlock = 0
        V = SM3.iv.clone()
    }

    fun update(`in`: ByteArray?, inOff: Int, len: Int) {
        val partLen = 64 - xBufOff
        var inputLen = len
        var dPos = inOff
        if (partLen < inputLen) {
            System.arraycopy(`in`, dPos, xBuf, xBufOff, partLen)
            inputLen -= partLen
            dPos += partLen
            doUpdate()
            while (inputLen > 64) {
                System.arraycopy(`in`, dPos, xBuf, 0, 64)
                inputLen -= 64
                dPos += 64
                doUpdate()
            }
        }
        System.arraycopy(`in`, dPos, xBuf, xBufOff, inputLen)
        xBufOff += inputLen
    }

    private fun doUpdate() {
        val B = ByteArray(64)
        var i = 0
        while (i < 64) {
            System.arraycopy(xBuf, i, B, 0, B.size)
            doHash(B)
            i += 64
        }
        xBufOff = 0
    }

    private fun doHash(B: ByteArray) {
        val tmp = CF(V, B)
        System.arraycopy(tmp, 0, V, 0, V.size)
        cntBlock += 1
    }

    private fun doFinal(): ByteArray {
        val B = ByteArray(64)
        val buffer = ByteArray(xBufOff)
        System.arraycopy(xBuf, 0, buffer, 0, buffer.size)
        val tmp = padding(buffer, cntBlock)
        var i = 0
        while (i < tmp.size) {
            System.arraycopy(tmp, i, B, 0, B.size)
            doHash(B)
            i += 64
        }
        return V
    }

    fun update(`in`: Byte) {
        val buffer = byteArrayOf(`in`)
        update(buffer, 0, 1)
    }

    val digestSize: Int
        get() = 32

    companion object {
        private const val BYTE_LENGTH = 32
        private const val BLOCK_LENGTH = 64
        private const val BUFFER_LENGTH = 64
    }
}

fun main(args: Array<String>) {
    val md = ByteArray(32)
    val msg1 = "abc".toByteArray()
    val sm3 = SM3Digest()
    sm3.update(msg1, 0, msg1.size)
    sm3.doFinal(md, 0)
    val s = bytesToHexStr(md)
    println(s)
}