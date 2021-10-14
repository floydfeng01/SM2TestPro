package com.froad.sm2testpro.utils

import com.froad.sm2testpro.extension.allTrim
import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray
import java.io.UnsupportedEncodingException
import java.util.*

/**
 * Created by FW on 2017/6/7.
 */
class PkcsInfoUtil {

    companion object {
        var hasHMap: HashMap<String, String>? = null
        private val base64EncodeChars = charArrayOf(
            'A', 'B', 'C',
            'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
            '3', '4', '5', '6', '7', '8', '9', '+', '/'
        )

        fun encode(data: ByteArray): String {
            val sb = StringBuffer()
            val len = data.size
            var i = 0
            while (i < len) {
                val b1: Int = data[i++].toInt() and 0xFF
                if (i == len) {
                    sb.append(base64EncodeChars[b1 ushr 2])
                    sb.append(base64EncodeChars[b1 and 0x3 shl 4])
                    sb.append("==")
                    break
                }
                val b2: Int = data[i++].toInt() and 0xFF
                if (i == len) {
                    sb.append(base64EncodeChars[b1 ushr 2])
                    sb.append(
                        base64EncodeChars[(b1 and 0x3) shl 4 or
                                ((b2 and 0xF0) ushr 4)]
                    )
                    sb.append(base64EncodeChars[b2 and 0xF shl 2])
                    sb.append("=")
                    break
                }
                val b3: Int = data[i++].toInt() and 0xFF
                sb.append(base64EncodeChars[b1 ushr 2])
                sb.append(
                    base64EncodeChars[(b1 and 0x3) shl 4 or
                            ((b2 and 0xF0) ushr 4)]
                )
                sb.append(
                    base64EncodeChars[(b2 and 0xF) shl 2 or
                            ((b3 and 0xC0) ushr 6)]
                )
                sb.append(base64EncodeChars[b3 and 0x3F])
            }
            return sb.toString()
        }
    }

    var hexString = ""
    var pkcs7: ByteArray? = null
        get() {
            field = hexString2ByteArray(hexString)
            return field
        }

    fun setTlvByTv(Tag: Byte, v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length / 2
        val mylen = getLenthBy16(lenth)
        val tagHex = bytesToHexStr(byteArrayOf(Tag))
        val all = tagHex + mylen + vHex
        hexString += all
    }

    fun setBoolean_TLV(v: Boolean?) {}
    fun setInteger_TLV(v: Int) {
        val myv = getLenthBy16(v)
        val lenth = myv.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "02$lenth16$myv"
    }

    fun setBitString_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "03$lenth16$vHex"
    }

    fun setOctetString_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "04$lenth16$vHex"
    }

    fun setObjectIdentifier_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "06$lenth16$vHex"
    }

    fun setObjectDescriptor_TLV(v: ByteArray?) {}

    fun setExternalInstancceOf_TLV(v: ByteArray?) {}

    fun setReal_TLV(v: ByteArray?) {}

    fun setENUMERATED_TLV(v: ByteArray?) {}

    fun setUTF8String_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "0C$lenth16$vHex"
    }

    fun setRELATIVE_OID_TLV(v: ByteArray?) {}

    fun setSEQUENCE_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length / 2
        val lenth16 = getLenthBy16(lenth)
        hexString += "30$lenth16$vHex"
    }

    fun packSEQUENCE_TLV() {
        val v = pkcs7
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length / 2
        val lenth16 = getLenthBy16(lenth)
        hexString = "30$lenth16$vHex"
    }

    fun setSET_SET_OF_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "31$lenth16$vHex"
    }

    fun addHeadSET_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString = "31$lenth16$vHex"
    }

    fun setNumeric_String_TLV(v: ByteArray?) {}
    fun setPrintable_String_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += "13$lenth16$vHex"
    }

    fun setIA5_String_TLV(v: String) {
        hexString += v
    }

    fun setTeletexString_T61String_TLV(v: ByteArray?) {}

    fun setVideotexString_TLV(v: ByteArray?) {}

    fun setUTCTime_TLV(v: ByteArray?) {}

    fun setGeneralizedTime_TLV(v: ByteArray?) {}

    fun setGraphicString_TLV(v: ByteArray?) {}

    fun setVisibleString_ISO646String_TLV(v: ByteArray?) {}

    fun setGeneralString_TLV(v: ByteArray?) {}

    fun setUniversalString_TLV(v: ByteArray?) {}

    fun setCHARACTER_STRING_TLV(v: ByteArray?) {}

    fun setBMPString_TLV(v: ByteArray?) {}

    fun setContext_TLV(v: ByteArray?) {
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString += ("A0$lenth16$vHex")
    }

    fun packContext_TLV() {
        val v = pkcs7
        val vHex = bytesToHexStr(v)
        val lenth = vHex!!.length
        val lenth16 = getLenthBy16(lenth / 2)
        hexString = "A0$lenth16$vHex"
    }

    fun setNull_TLV() {
        hexString += "0500"
    }

    fun getLenthBy16(value: Int): String {
        var value16 = Integer.toHexString(value)
        val len = value16.length
        if (len % 2 != 0) {
            value16 = "0$value16"
        }
        val lenNew = value16.length / 2
        if (value > 128) {
            value16 = "8$lenNew$value16"
        }
        if (value == 128) {
            value16 = "81$value16"
        }
        return value16
    }

    fun makeMapTable() {
        hasHMap = HashMap()
        hasHMap!!["CN"] = "550403"
        hasHMap!!["SN"] = "550404"
        hasHMap!!["C"] = "550406"
        hasHMap!!["L"] = "550407"
        hasHMap!!["ST"] = "550408"
        hasHMap!!["street"] = "550409"
        hasHMap!!["O"] = "55040A"
        hasHMap!!["OU"] = "55040B"
        hasHMap!!["title"] = "55040C"
        hasHMap!!["member"] = "55041F"
        hasHMap!!["owner"] = "550420"
        hasHMap!!["seeAlso"] = "550422"
        hasHMap!!["name"] = "550429"
        hasHMap!!["GN"] = "55042A"
        hasHMap!!["initials"] = "55042B"
        hasHMap!!["dnQualifier"] = "55042E"
        hasHMap!!["dmdName"] = "550436"
        hasHMap!!["role"] = "550448"
    }

    fun packSM2SEQUENCEByDN_Oid(oid: String) {
        makeMapTable()
        val oidArry = oid.split(",").toTypedArray()
        var res = ""
        var i = 1
        for (j in 2 downTo 0) {
            val tempArry = oidArry[j].split("=").toTypedArray()
            if (tempArry != null && tempArry.size >= 2) {
                tempArry[0] = tempArry[0].allTrim()
                val value = hasHMap!![tempArry[0]]
                if (value == null || "" == value) {
                    setObjectIdentifier_TLV(hexString2ByteArray("2a864886f70d010901"))
                    tempArry[1] = tempArry[1].replace("#", "")
                    setIA5_String_TLV(tempArry[1])
                } else {
                    setObjectIdentifier_TLV(hexString2ByteArray(value))
                    try {
                        if (i == 3) setPrintable_String_TLV(tempArry[1].toByteArray(charset("gb2312"))) else {
                            setUTF8String_TLV(tempArry[1].toByteArray(charset("gb2312")))
                        }
                    } catch (localUnsupportedEncodingException: UnsupportedEncodingException) {
                    }
                }
                packSEQUENCE_TLV()
            }
            addHeadSET_TLV(pkcs7)
            res = hexString + res
            clear()
            ++i
        }
        hexString = res
        packSEQUENCE_TLV()
    }

    fun packSEQUENCEByDN_Oid(oid: String) {
        makeMapTable()
        val oidArry = oid.split(",").toTypedArray()
        var res = ""
        var i = 1
        for (temp in oidArry) {
            val tempArry = temp.split("=").toTypedArray()
            if (tempArry != null && tempArry.size >= 2) {
                tempArry[0] = tempArry[0].allTrim()
                val value = hasHMap!![tempArry[0]]
                if (value == null || "" == value) {
                    setObjectIdentifier_TLV(hexString2ByteArray("2a864886f70d010901"))
                    tempArry[1] = tempArry[1].replace("#", "")
                    setIA5_String_TLV(tempArry[1])
                } else {
                    setObjectIdentifier_TLV(hexString2ByteArray(value))
                    try {
                        if (i == 3) setPrintable_String_TLV(tempArry[1].toByteArray(charset("gb2312"))) else {
                            setUTF8String_TLV(tempArry[1].toByteArray(charset("gb2312")))
                        }
                    } catch (localUnsupportedEncodingException: UnsupportedEncodingException) {
                    }
                }
                packSEQUENCE_TLV()
            }
            addHeadSET_TLV(pkcs7)
            res = hexString + res
            clear()
            ++i
        }
        hexString = res
        packSEQUENCE_TLV()
    }

    fun clear() {
        hexString = ""
    }

}