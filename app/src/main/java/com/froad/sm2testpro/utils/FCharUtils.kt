package com.froad.sm2testpro.utils

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.text.TextUtils
import android.util.DisplayMetrics
import org.bc.asn1.x509.X509CertificateStructure
import java.io.File
import java.io.IOException
import java.io.UnsupportedEncodingException
import java.math.BigInteger
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import java.util.regex.Matcher
import java.util.regex.Pattern
import javax.security.cert.CertificateEncodingException
import javax.security.cert.X509Certificate

/**
 * @ClassName: FCharUtils
 * @Description: TODO
 * @author: froad-Floyd_feng 2015年7月28日
 * @modify: froad-Floyd_feng 2015年7月28日
 */
object FCharUtils {
    private const val TAG = "FCharUtils"
    fun stringToASCIIArray(s: String?): CharArray {
        return s?.toCharArray() ?: CharArray(0)
    }

    /**
     * @param s
     * @return
     */
    fun stringToByteArray(s: String): ByteArray {
        val sl = s.length
        val charArray = ByteArray(sl)
        for (i in 0 until sl) {
            val charElement = s[i]
            charArray[i] = charElement.toByte()
        }
        return charArray
    }

    /**
     * @param bs
     * @return
     */
    fun byteToCharArray(bs: ByteArray): CharArray {
        val bsl = bs.size
        val charArray = CharArray(bsl)
        for (i in 0 until bsl) {
            charArray[i] = (bs[i].toChar().toInt() and 0x00FF).toChar()
        }
        return charArray
    }

    /**
     * @param b
     * @return
     */
    fun byte2char(b: Byte): Char {
        return (b.toChar().toInt() and 0x00FF).toChar()
    }

    /**
     * @Title: int2HexStr
     * @Description: 将int型转换为16进制字符串，最大允许四字节长度
     * @author: Floyd_feng 2015年11月19日
     * @modify: Floyd_feng 2015年11月19日
     * @param: i
     */
    @JvmStatic
    fun int2HexStr(i: Int): String {
        var si = Integer.toHexString(i)
        if (si.length % 2 != 0) {
            si = "0$si"
        }
        si = si.toUpperCase()
        return si
    }

    /**
     * int转Hex编码，2字节，反转
     * @param i
     * @return
     */
    fun int2HexStr2Reversal(i: Int): String {
        var i = i
        i = i and 0xFFFF
        val si = Integer.toHexString(i)
        val sil = 4 - si.length
        if (sil <= 0) {
            return si.substring(0, 4)
        }
        val sbf = StringBuffer()
        for (k in 0 until sil) {
            sbf.append("0")
        }
        sbf.append(si)
        var st = sbf.toString().toUpperCase()
        st = st.substring(2, 4) + st.substring(0, 2)
        return st
    }

    /**
     * 将长度转换为两字节Hex编码
     * @param i
     * @return
     */
    fun int2HexStr2(i: Int): String {
        var i = i
        i = i and 0xFFFF
        var si = Integer.toHexString(i)
        val sl = si.length
        si = if (sl < 4) {
            val sbf = StringBuffer()
            for (k in 0 until 4 - sl) {
                sbf.append("0")
            }
            sbf.append(si)
            sbf.toString()
        } else {
            si.substring(sl - 4)
        }
        si = si.toUpperCase()
        return si
    }

    /**
     * 将数字转换为BCD码
     *
     * @param i
     * @return
     */
    fun int2BCDStr(i: Int): String {
        var `is` = "" + i
        if (`is`.length % 2 != 0) {
            `is` = "0$`is`"
        }
        return `is`
    }

    /**
     * 将数字转换为二进制码
     *
     * @param i
     * @return
     */
    fun int2BinaryStr(i: Int): String {
        var i = i
        val it = Integer.toBinaryString(i)
        val sbf = StringBuffer()
        val itLen = 8 - it.length
        val k = 0
        while (i < itLen) {
            sbf.append("0")
            i++
        }
        sbf.append(it)
        return sbf.toString()
    }

    /**
     * 将长度转换，如果大于127，则用两字节表示，第一字节高位高字节不参与计算，否则，用一字节表示
     *
     * @param l
     * @return
     */
    fun len2HexStr(l: Int): String {
        var s = ""
        if (l > 127) { //长度大于127则用两字节表示
            var ol1: Int = (l shr 8)
            val ol2: Int = (l - (ol1 shl 8))
            ol1 += 0x80
            s = int2HexStr(ol1) + int2HexStr(ol2)
        } else {
            s = int2HexStr(l)
        }
        s = s.uppercase()
        return s
    }

    /**
     * EID指令交互通过P1P2表示地址偏移
     * @param l
     * @return
     */
    fun len2P1P2(l: Int): Array<String>? {
        var st = Integer.toHexString(l)
        val stl = 4 - st.length
        if (stl < 0) {
            return null
        }
        for (i in 0 until stl) {
            st = "0$st"
        }
        return arrayOf(st.substring(0, 2), st.substring(2))
    }

    /**
     * 将长度字符串转换为数字
     *
     * @param st
     * @return
     */
    fun hexStr2Len(st: String?): Int {
        return if (st == null || "" == st) {
            0
        } else {
            if (st.length == 4) { //长度大于127则用两字节表示
                val t1 = st.substring(0, 2)
                val t2 = st.substring(2, 4)
                ((t1.toInt(16) - 0x80) shl 8) + t2.toInt(16)
            } else if (st.length == 2 || st.length == 1) {
                st.toInt(16)
            } else {
                0
            }
        }
    }

    /**
     * 将长度字符串转换为数字,需要反转
     *
     * @param st
     * @return
     */
    fun hexStr2LenRev(st: String?): Int {
        return if (st == null || "" == st) {
            0
        } else {
            if (st.length == 4) {
                val t1 = st.substring(0, 2)
                val t2 = st.substring(2, 4)
                (t2.toInt(16) shl 8) + t1.toInt(16)
            } else if (st.length == 2 || st.length == 1) {
                st.toInt(16)
            } else {
                0
            }
        }
    }

    /**
     * BCD码字符串转成int
     *
     * @param st
     * @return 失败默认返回-1
     */
    fun bcdStr2Int(st: String?): Int {
        return if (st == null || "" == st) {
            -1
        } else { //十进制转换
            st.toInt(10)
        }
    }

    /**
     * 将字符串转换为16进制格式字符串
     *
     * @param s
     * @return
     */
    fun string2HexStr(s: String): String? {
        try {
            val bs = s.toByteArray(charset("UTF-8"))
            return showResult16Str(bs)
        } catch (ue: UnsupportedEncodingException) {
            ue.printStackTrace()
        }
        return null
    }

    /**
     * 将字符串转换为16进制格式字符串
     *
     * @param s
     * @param enCode
     * @return
     */
    fun string2HexStr(s: String, enCode: String?): String? {
        try {
            val bs = s.toByteArray(charset(enCode!!))
            return showResult16Str(bs)
        } catch (ue: UnsupportedEncodingException) {
            ue.printStackTrace()
        }
        return null
    }

    /**
     * 将16进制字符串转换为常规字符串
     *
     * @param s 16进制字符串
     * @param s 编码
     * @return
     */
    fun hexStr2String(s: String, encodeType: String?): String? {
        try {
            return String(hexString2ByteArray(s)!!, charset(encodeType!!))
        } catch (ue: UnsupportedEncodingException) {
            ue.printStackTrace()
        }
        return null
    }

    /**
     * hex字符串转unicode编码
     * @param s
     * @return
     */
    fun hexStr2UCString(s: String?): String {
        if (s == null) {
            return ""
        }
        val sl = s.length
        if (sl % 4 != 0) {
            return ""
        }
        val sbf = StringBuffer()
        var i = 0
        while (i < sl) {
            sbf.append(s.substring(i, i + 4).toInt(16).toChar())
            i += 4
        }
        return sbf.toString()
    }

    /**
     * 将16进制数据转换为LV格式数据
     *
     * @param s
     * @return
     */
    fun hexStr2LV(s: String?): String {
        return if (s == null || "" == s) {
            ""
        } else (len2HexStr(s.length / 2) + s)
    }

    /**
     * 在数据前补一字节的长度
     * @param s
     * @return
     */
    fun hexStr2LV_1(s: String?): String {
        return if (s == null || "" == s) {
            ""
        } else (int2HexStr(s.length / 2) + s)
    }

    /**
     * 在数据前补两字节的长度
     * @param s
     * @return
     */
    @JvmStatic
    fun hexStr2LV_2(s: String?): String {
        return if (s == null || "" == s) {
            ""
        } else (int2HexStr2(s.length / 2) + s)
    }

    /**
     * @Title: hexString2ByteArray
     * @Description: 将16进制字符串转成byte数组
     * @author: Floyd_feng 2015年12月10日
     * @modify: Floyd_feng 2015年12月10日
     * @param: @param bs
     * @param: @return
     * @throws：
     */
    @JvmStatic
    fun hexString2ByteArray(bs: String): ByteArray? {
        val bsLength = bs.length
        if (bsLength % 2 != 0) {
            return null
        }
        val cs = ByteArray(bsLength / 2)
        var st = ""
        var i = 0
        while (i < bsLength) {
            st = bs.substring(i, i + 2)
            cs[i / 2] = st.toInt(16).toByte()
            i += 2
        }
        return cs
    }

    /**
     * @throws
     * @Title: showResult16Str
     * @Description: 将byte数组转成16进制字符串
     * @author: Floyd_feng 2015年12月10日
     * @modify: Floyd_feng 2015年12月10日
     * @param: @param b
     * @param: @return
     */
    @SuppressLint("DefaultLocale")
    fun showResult16Str(b: ByteArray?): String {
        if (b == null) {
            return ""
        }
        val sbf = StringBuffer()
        val bl = b.size
        var bt: Byte
        var bts = ""
        var btsl: Int
        for (i in 0 until bl) {
            bt = b[i]
            bts = Integer.toHexString(bt.toInt())
            btsl = bts.length
            bts = when {
                btsl == 1 -> "0${bts.uppercase()}"
                btsl > 2 -> bts.substring(btsl - 2).uppercase()
                else -> bts.uppercase()
            }
            // System.out.println("i::"+i+">>>bts::"+bts);
            sbf.append(bts)
        }
        return sbf.toString()
    }

    /**
     * @throws
     * @Title: showResult0xStr
     * @Description: 将byte数组转成16进制字符串，0x01 0x02 0x03形式
     * @author: Floyd_feng 2015年12月10日
     * @modify: Floyd_feng 2015年12月10日
     * @param: @param b
     * @param: @return
     */
    fun showResult0xStr(b: ByteArray): String {
        var rs = ""
        val bl = b.size
        var bt: Byte
        var bts = ""
        var btsl: Int
        for (i in 0 until bl) {
            bt = b[i]
            bts = Integer.toHexString(bt.toInt())
            btsl = bts.length
            bts = when {
                btsl > 2 -> "0x${bts.substring(btsl - 2)}"
                btsl == 1 -> "0x0$bts"
                else -> "0x$bts"
            }
            // System.out.println("i::"+i+">>>bts::"+bts);
            rs += "$bts "
        }
        // System.out.println("rs::"+rs);
        return rs
    }

    /**
     * @param str
     */
    fun enc21Int(str: String): String {
        return try {
            val len = str.length
            var endi = 0
            var sum = 0
            val cs = str.toCharArray()
            for (i in 0 until len) {
                sum += (cs[i].code * (if (i % 2 == 0) 2 else 1))
            }
            // System.out.println("enc21Int>>>sum::"+sum);
            endi = (10 - sum % 10) % 10
            str + endi
        } catch (e: Exception) {
            "ERROR"
        }
    }

    /**
     * @param str
     */
    fun checkOutStr_21(str: String): String {
        return try {
            val len = str.length
            val endi = str.substring(len - 1, len).toInt()
            var sum = 0
            val cs = str.substring(0, len - 1).toCharArray()
            var i1 = 2
            for (i in 0 until len - 1) {
                i1 = (if (i % 2 == 0) 2 else 1)
                sum += cs[i].code * i1
            }
            // System.out.println("checkOutStr_21>>>sum::"+sum);
            if (endi == (10 - sum % 10) % 10) {
                str.substring(0, len - 1)
            } else
                "ERROR"
        } catch (e: Exception) {
             "ERROR"
        }
    }

    /**
     * @param str
     */
    fun encSumInt(str: String): String {
        return try {
            val len = str.length
            var sum = 0
            val cs = str.toCharArray()
            for (i in 0 until len) {
                sum += cs[i].code
            }
            val sumStr = Integer.toHexString(sum)
            // System.out.println("sum_str::"+sum_str);
            val ssl = sumStr.length
            if (ssl < 2) {
                val nc = sum.toChar()
                str + nc
            } else {
                val sumStrSub = sumStr.substring(ssl - 2)
                val ci = Integer.decode("0x$sumStrSub")
                val c = ci.toChar()
                str + c
            }
        } catch (e: Exception) {
            "ERROR"
        }
    }

    /**
     * @throws
     * @Title: checkOutStr_sum
     * @Description: 通过校验和的方式校验指令数据
     * @author: Floyd_feng 2015年7月27日
     * @modify: Floyd_feng 2015年7月27日
     */
    fun checkOutStrSum(str: String): String {
        return try {
            val len = str.length
            if (len < 3) {
                return "ERROR"
            }
            val strInt = str.substring(0, len - 1)
            val strSub = str.substring(len - 1, len)
            var sum = 0
            val cs = strInt.toCharArray()
            for (i in 0 until len - 1) {
                sum += cs[i].code
            }
            val sumStr = Integer.toHexString(sum)
            // System.out.println("checkOutStr_sum>>>sum_str::"+sum_str);
            val ssl = sumStr.length
            if (ssl < 2) {
                if (strSub[0].code == sum) {
                    return strInt
                }
            } else {
                val sumStrSub = sumStr.substring(ssl - 2)
                if (strSub[0].code == Integer.decode("0x$sumStrSub")) {
                    return strInt
                }
            }
            "ERROR"
        } catch (e: Exception) {
            return "ERROR"
        }
    }

    /**
     * @param str
     */
    fun encLRCInt(str: String): Char {
        val len = str.length
        var sum = 0
        val cs = str.toCharArray()
        for (i in 0 until len) {
            sum += cs[i].code
        }
        var sumStr = Integer.toHexString(sum)
        // System.out.println("sum_str::"+sum_str);
        val ssl = sumStr.length
        if (ssl > 2) {
            sumStr = sumStr.substring(ssl - 2)
        }
        val ci = Integer.decode("0x$sumStr")
        val cF = 0xFF
        val c1 = 0x01
        val nc = cF - ci
        return ((nc + c1) and 0x00FF).toChar()
    }

    /**
     * @param str
     */
    fun checkOutStr_LRC(str: String): Boolean {
        val len = str.length
        if (len < 3) {
            return false
        }
        val strInt = str.substring(0, len - 1)
        val strSub = str.substring(len - 1, len)
        var sum = 0
        val cs = strInt.toCharArray()
        for (i in 0 until len - 1) {
            sum += cs[i].code
        }
        var sumStr = Integer.toHexString(sum)
        // System.out.println("checkOutStr_sum>>>sum_str::"+sum_str);
        val ssl = sumStr.length
        if (ssl > 2) {
            sumStr = sumStr.substring(ssl - 2)
        }
        val ci = Integer.decode("0x$sumStr")
        val cF = 0xFF
        val c1 = 0x01
        val nc = cF - ci
        val ncLrc = ((nc + c1) and 0x00FF)
        // System.out.println("checkOutStr_sum>>>ncLrc::"+(int)ncLrc);
        return strSub[0].code == ncLrc
    }

    /**
     * @throws
     * @Title: encXORInt
     * @Description: TODO
     * @author: Floyd_feng 2015年7月28日
     * @modify: Floyd_feng 2015年7月28日
     */
    fun encXORInt(str: String): Char {
        val len = str.length
        var tor = 0
        val cs = str.toCharArray()
        for (i in 0 until len) {
            tor = (tor xor (cs[i].code))
        }
        // System.out.println("tor::"+tor+">>>int(tor)::"+(int)tor);
        return tor.toChar()
    }

    /**
     * @param str
     */
    fun checkOutStr_XOR(str: String): Boolean {
        val len = str.length
        if (len < 3) {
            return false
        }
        val strInt = str.substring(0, len - 1)
        val strSub = str.substring(len - 1, len)
        var tor = 0
        val cs = strInt.toCharArray()
        for (i in 0 until len - 2) {
            tor = (tor xor cs[i].code)
        }
        // System.out.println("tor::"+tor+">>>int(tor)::"+(int)tor);
        return strSub[0].code == tor
    }

    /**
     * 检测数字字符串
     *
     * @param str
     * @return
     */
    fun checkNum(str: String): Boolean {
        val regEx = "[^0-9]"
        val p = Pattern.compile(regEx)
        var m: Matcher
        val pns = str.toCharArray()
        val pl = pns.size
        for (i in 0 until pl) {
            m = p.matcher("${pns[i]}")
            if (m.find()) {
                return false
            }
        }
        return true
    }

    /**
     * 检测数字和点字符串
     *
     * @param str
     * @return
     */
    fun checkNumIsMoney(str: String): Boolean {
        val regEx = "[^0-9.]"
        val p = Pattern.compile(regEx)
        var m: Matcher
        val pns = str.toCharArray()
        val pl = pns.size
        for (i in 0 until pl) {
            m = p.matcher("${pns[i]}")
            if (m.find()) {
                return false
            }
        }
        return true
    }

    /**
     * 检测数字和字母字符串
     *
     * @param str
     * @return
     */
    fun checkNumOrZ(str: String): Boolean {
        val regEx = "[^(0-9a-zA-Z)]"
        val p = Pattern.compile(regEx)
        var m: Matcher
        val pns = str.toCharArray()
        val pl = pns.size
        for (i in 0 until pl) {
            m = p.matcher("${pns[i]}")
            if (m.find()) {
                return false
            }
        }
        return true
    }

    /**
     * 检测十六进制字符串
     *
     * @param str
     * @return
     */
    fun checkHexStr(str: String): Boolean {
        val regEx = "[^(0-9a-fA-F)]"
        val p = Pattern.compile(regEx)
        var m: Matcher
        val pns = str.toCharArray()
        val pl = pns.size
        for (i in 0 until pl) {
            m = p.matcher("${pns[i]}")
            if (m.find()) {
                return false
            }
        }
        return true
    }

    /**
     * 检测蓝牙4.0
     */
    fun checkBleVer(): Boolean {
        try {
            val cls = Class
                .forName("android.bluetooth.BluetoothAdapter\$LeScanCallback")
            if (cls != null) {
                return true
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    @SuppressLint("DefaultLocale")
    fun toHexCode(data: ByteArray, offset: Int, length: Int): String {
        val stringBuilder = StringBuilder(data.size * 2)
        for (i in offset until offset + length) {
            stringBuilder.append(String.format("%02X", data[i]).uppercase())
        }
        return stringBuilder.toString()
    }

    fun verifyIP(ipStr: String?): Boolean {
        if (ipStr == null || "" == ipStr) {
            return false
        }
        val ips = ipStr.split("\\.").toTypedArray()
        val ipsl = ips.size
        if (ipsl != 4) {
            return false
        }
        for (i in 0 until ipsl) {
            if (!checkNum(ips[i]) || ips[i].length > 3 || ips[i].isEmpty()) {
                return false
            }
        }
        return true
    }

    fun cutBytes(d: ByteArray?, start: Int, offest: Int): ByteArray {
        val len = offest - start
        val resB = ByteArray(len)
        System.arraycopy(d, start, resB, 0, len)
        return resB
    }

    fun showUninstallAPKSignatures(apkPath: String?): String? {
        val PATH_PackageParser = "android.content.pm.PackageParser"
        try {
            // apk包的文件路径
            // 这是一个Package 解释器, 是隐藏的
            // 构造函数的参数只有一个, apk文件的路径
            // PackageParser packageParser = new PackageParser(apkPath);
            val pkgParserCls = Class.forName(PATH_PackageParser)
            var typeArgs = arrayOfNulls<Class<*>?>(1)
            typeArgs[0] = String::class.java
            val pkgParserCt = pkgParserCls.getConstructor(*typeArgs)
            var valueArgs = arrayOfNulls<Any>(1)
            valueArgs[0] = apkPath
            val pkgParser = pkgParserCt.newInstance(*valueArgs)
            // 这个是与显示有关的, 里面涉及到一些像素显示等等, 我们使用默认的情况
            val metrics = DisplayMetrics()
            metrics.setToDefaults()
            // PackageParser.Package mPkgInfo = packageParser.parsePackage(new
            // File(apkPath), apkPath,
            // metrics, 0);
            typeArgs = arrayOfNulls<Class<*>?>(4)
            typeArgs[0] = File::class.java
            typeArgs[1] = String::class.java
            typeArgs[2] = DisplayMetrics::class.java
            typeArgs[3] = Integer.TYPE
            val pkgParser_parsePackageMtd = pkgParserCls.getDeclaredMethod(
                "parsePackage",
                *typeArgs
            )
            valueArgs = arrayOfNulls(4)
            valueArgs[0] = File(apkPath)
            valueArgs[1] = apkPath
            valueArgs[2] = metrics
            valueArgs[3] = PackageManager.GET_SIGNATURES
            val pkgParserPkg = pkgParser_parsePackageMtd.invoke(pkgParser, *valueArgs)
            typeArgs = arrayOfNulls<Class<*>?>(2)
            typeArgs[0] = pkgParserPkg.javaClass
            typeArgs[1] = Integer.TYPE
            val pkgParser_collectCertificatesMtd = pkgParserCls.getDeclaredMethod(
                "collectCertificates",
                *typeArgs
            )
            valueArgs = arrayOfNulls(2)
            valueArgs[0] = pkgParserPkg
            valueArgs[1] = PackageManager.GET_SIGNATURES
            pkgParser_collectCertificatesMtd.invoke(pkgParser, *valueArgs)
            // 应用程序信息包, 这个公开的, 不过有些函数, 变量没公开
            val packageInfoFld = pkgParserPkg.javaClass.getDeclaredField("mSignatures")
            val info = packageInfoFld[pkgParserPkg] as Array<Signature>
            return info[0].toCharsString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun getMD5(decript: Signature): String {
        return try {
            val digest = MessageDigest
                .getInstance("MD5")
            digest.update(decript.toByteArray())
            val messageDigest = digest.digest()
            // Create Hex String
            val hexString = StringBuffer()
            // 字节数组转换为 十六进制 数
            for (i in messageDigest.indices) {
                val shaHex = Integer.toHexString(messageDigest[i].toInt() and 0xFF).uppercase()
                if (shaHex.length < 2) {
                    hexString.append(0)
                }
                hexString.append(shaHex)
            }
            hexString.toString()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            ""
        }
    }

    /**
     * byte[]转hex
     *
     * @param src
     * @return
     */
    @JvmStatic
    fun bytesToHexStr(src: ByteArray?): String? {
        val stringBuilder = StringBuilder("")
        if (src == null || src.isEmpty()) {
            return null
        }
        for (i in src.indices) {
            val v: Int = src[i].toInt() and 0xFF
            val hv = Integer.toHexString(v)
            if (hv.length < 2) {
                stringBuilder.append(0)
            }
            stringBuilder.append(hv)
        }
        return stringBuilder.toString().uppercase()
    }

    /**
     * hex转byte[]
     *
     * @param hexString
     * @return
     */
    fun hexStrToBytes(hexString: String?): ByteArray? {
        var hexString = hexString
        if (hexString == null || hexString == "") {
            return null
        }
        hexString = hexString.uppercase()
        val length = hexString.length / 2
        val hexChars = hexString.toCharArray()
        val d = ByteArray(length)
        for (i in 0 until length) {
            val pos = i * 2
            d[i] = (((charToByte(hexChars[pos]).toInt() shl 4) or charToByte(hexChars[pos + 1]).toInt()) and 0xFF).toByte()
        }
        return d
    }

    /**
     * Convert char to byte
     *
     * @param c char
     * @return byte
     */
    private fun charToByte(c: Char): Byte {
        return "0123456789ABCDEF".indexOf(c).toByte()
    }

    /**
     * 解析LV格式数据如果len大于80则由两位表示
     * @param data 需要解析的数据
     * @param hasKey LV数据之前是否有一个字节的key版本号
     * @return
     */
    fun parseDataLV(data: String?, hasKey: Boolean): ArrayList<String>? {
        var list: ArrayList<String>? = null
        if (data == null || "" == data) {
            return list
        }
        list = ArrayList()
        val sl = data.length
        var curIndex = 0 //当前偏移
        var tLen = ""
        var tLenInt = 0 //数据长度
        var tValue = "" //数据值
        if (hasKey) {
            val keyVersion = data.substring(curIndex, curIndex + 2) //秘钥版本
            curIndex += 2
        }
        while (curIndex < sl) {
            tLen = data.substring(curIndex, curIndex + 2)
            curIndex += 2
            tLenInt = hexStr2Len(tLen)
            if (tLenInt == 0) { //L为0，直接解析下一个数据域
                continue
            }
            if (tLenInt >= 0x80) {
                tLen = data.substring(curIndex - 2, curIndex + 2)
                curIndex += 2
                tLenInt = hexStr2Len(tLen)
            }
            if (curIndex + tLenInt * 2 > sl) { //长度有误
                return null
            }
            if (hasKey) {
                //加密Data
                val encData = data.substring(curIndex, curIndex + tLenInt * 2)
                curIndex += tLenInt * 2
                list.add(encData)

                //mac ,固定四字节
                tLenInt = 4
                val mac = data.substring(curIndex, curIndex + tLenInt * 2)
                curIndex += tLenInt * 2
                list.add(mac)
            } else {
                tValue = data.substring(curIndex, curIndex + tLenInt * 2)
                curIndex += tLenInt * 2
                list.add(tValue)
            }
        }
        return list
    }

    /**
     * 将签名数据转换为Pkcs7格式数据
     * @param text
     * @param x509Certificate
     * @param sig
     * @return
     */
    fun makep7bPack(text: ByteArray?, x509Certificate: X509Certificate?, sig: ByteArray?): String {
        if (x509Certificate == null) {
            return ""
        }
        val signedData = PkcsInfoUtil()
        signedData.setInteger_TLV(Integer.valueOf(1))
        val digestAlgorithmId = PkcsInfoUtil()
        digestAlgorithmId.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 1, 5))
        digestAlgorithmId.setNull_TLV()
        digestAlgorithmId.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(digestAlgorithmId.pkcs7)
        val content = PkcsInfoUtil()
        content.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 7, 1))
        val contextPkcsInfoUtil = PkcsInfoUtil()
        contextPkcsInfoUtil.setOctetString_TLV(text)
        content.setContext_TLV(contextPkcsInfoUtil.pkcs7)
        signedData.setSEQUENCE_TLV(content.pkcs7)
        try {
            signedData.setContext_TLV(x509Certificate.encoded)
        } catch (localCertificateEncodingException: CertificateEncodingException) {
        }
        val signValuePkcsInfoUtil = PkcsInfoUtil()
        signValuePkcsInfoUtil.setInteger_TLV(Integer.valueOf(1))
        val cerInfoPkcsInfoUtil = PkcsInfoUtil()
        cerInfoPkcsInfoUtil.packSEQUENCEByDN_Oid(x509Certificate.issuerDN.name)
        cerInfoPkcsInfoUtil.setTlvByTv(2.toByte(), x509Certificate.serialNumber.toByteArray())
        signValuePkcsInfoUtil.setSEQUENCE_TLV(cerInfoPkcsInfoUtil.pkcs7)
        val sigalg = PkcsInfoUtil()
        sigalg.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 1, 5))
        sigalg.setNull_TLV()
        signValuePkcsInfoUtil.setSEQUENCE_TLV(sigalg.pkcs7)
        val encodealgPkcsInfoUtil = PkcsInfoUtil()
        encodealgPkcsInfoUtil.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 1, 1))
        encodealgPkcsInfoUtil.setNull_TLV()
        signValuePkcsInfoUtil.setSEQUENCE_TLV(encodealgPkcsInfoUtil.pkcs7)
        signValuePkcsInfoUtil.setOctetString_TLV(sig)
        signValuePkcsInfoUtil.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(signValuePkcsInfoUtil.pkcs7)
        signedData.packSEQUENCE_TLV()
        val retPkcsInfoUtil = PkcsInfoUtil()
        retPkcsInfoUtil.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 7, 2))
        retPkcsInfoUtil.setContext_TLV(signedData.pkcs7)
        retPkcsInfoUtil.packSEQUENCE_TLV()
        return PkcsInfoUtil.encode(retPkcsInfoUtil.pkcs7!!)
    }

    /**
     * 将签名数据转换为Pkcs7格式数据
     * @param text
     * @param x509Certificate
     * @param sig
     * @return
     */
    fun makeRSA2048p7bPack(
        text: ByteArray?,
        x509Certificate: X509Certificate?,
        sig: ByteArray?
    ): String {
        if (x509Certificate == null) {
            return ""
        }
        val signedData = PkcsInfoUtil()
        signedData.setInteger_TLV(Integer.valueOf(1))
        val digestAlgorithmId = PkcsInfoUtil()
        digestAlgorithmId.setObjectIdentifier_TLV(byteArrayOf(96, -122, 72, 1, 101, 3, 4, 2, 1))
        digestAlgorithmId.setNull_TLV()
        digestAlgorithmId.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(digestAlgorithmId.pkcs7)
        val content = PkcsInfoUtil()
        content.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 7, 1))
        val contextMakePackage = PkcsInfoUtil()
        contextMakePackage.setOctetString_TLV(text)
        content.setContext_TLV(contextMakePackage.pkcs7)
        signedData.setSEQUENCE_TLV(content.pkcs7)
        if (x509Certificate != null) {
            try {
                signedData.setContext_TLV(x509Certificate.encoded)
            } catch (localCertificateEncodingException: CertificateEncodingException) {
            }
        }
        val signValueMakePackage = PkcsInfoUtil()
        signValueMakePackage.setInteger_TLV(Integer.valueOf(1))
        val cerInfoMakePackage = PkcsInfoUtil()
        cerInfoMakePackage.packSEQUENCEByDN_Oid(x509Certificate.issuerDN.name)
        cerInfoMakePackage.setTlvByTv(2.toByte(), x509Certificate.serialNumber.toByteArray())
        signValueMakePackage.setSEQUENCE_TLV(cerInfoMakePackage.pkcs7)
        val sigalg = PkcsInfoUtil()
        sigalg.setObjectIdentifier_TLV(byteArrayOf(96, -122, 72, 1, 101, 3, 4, 2, 1))
        sigalg.setNull_TLV()
        signValueMakePackage.setSEQUENCE_TLV(sigalg.pkcs7)
        val encodealgMakePackage = PkcsInfoUtil()
        encodealgMakePackage.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 1, 1))
        encodealgMakePackage.setNull_TLV()
        signValueMakePackage.setSEQUENCE_TLV(encodealgMakePackage.pkcs7)
        signValueMakePackage.setOctetString_TLV(sig)
        signValueMakePackage.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(signValueMakePackage.pkcs7)
        signedData.packSEQUENCE_TLV()
        val retMakePackage = PkcsInfoUtil()
        retMakePackage.setObjectIdentifier_TLV(byteArrayOf(42, -122, 72, -122, -9, 13, 1, 7, 2))
        retMakePackage.setContext_TLV(signedData.pkcs7)
        retMakePackage.packSEQUENCE_TLV()
        return PkcsInfoUtil.encode(retMakePackage.pkcs7!!)
    }

    /**
     * 将签名数据转换为Pkcs7格式数据
     * @param text
     * @param x509CertificateStructure
     * @param sig
     * @return
     */
    fun makep7bPackSM2(
        text: ByteArray?,
        x509CertificateStructure: X509CertificateStructure?,
        sig: ByteArray?
    ): String {
        if (x509CertificateStructure == null) {
            return ""
        }
        val signedData = PkcsInfoUtil()
        signedData.setInteger_TLV(Integer.valueOf(1))
        val digestAlgorithmId = PkcsInfoUtil()
        digestAlgorithmId.setObjectIdentifier_TLV(byteArrayOf(42, -127, 28, -49, 85, 1, -125, 17))
        digestAlgorithmId.setNull_TLV()
        digestAlgorithmId.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(digestAlgorithmId.pkcs7)
        val content = PkcsInfoUtil()
        content.setObjectIdentifier_TLV(byteArrayOf(42, -127, 28, -49, 85, 6, 1, 4, 2, 1))
        val contextPkcsInfoUtil = PkcsInfoUtil()
        contextPkcsInfoUtil.setOctetString_TLV(text)
        content.setContext_TLV(contextPkcsInfoUtil.pkcs7)
        signedData.setSEQUENCE_TLV(content.pkcs7)
        try {
            signedData.setContext_TLV(x509CertificateStructure.encoded)
        } catch (e: IOException) {
        }
        val signValuePkcsInfoUtil = PkcsInfoUtil()
        signValuePkcsInfoUtil.setInteger_TLV(Integer.valueOf(1))
        val cerInfoPkcsInfoUtil = PkcsInfoUtil()
        val issuer: String = x509CertificateStructure.issuer.toString() //颁发者
//            if (!"".equals(issuer) && issuer != null) {
//                String issuers[] = issuer.split(",");
//                String issuerId = issuers[2].substring(issuers[2].indexOf("=") + 1);//证书发行单位编号
//                String issuerName = issuers[1].substring(issuers[1].indexOf("=") + 1);//证书发行单位名称
//                System.out.println("证书发行单位编号 ID=" + issuerId);
//                System.out.println("证书发行单位名称 NAME=" + issuerName);
//            }
        cerInfoPkcsInfoUtil.packSM2SEQUENCEByDN_Oid(x509CertificateStructure.issuer.toString())
        val serialNumberStr: String = x509CertificateStructure.serialNumber.toString()
        val serialNumber: String =
            x509CertificateStructure.serialNumber.positiveValue.toString()
        cerInfoPkcsInfoUtil.setTlvByTv(
            2.toByte(),
            x509CertificateStructure.serialNumber.positiveValue.toByteArray()
        )
        signValuePkcsInfoUtil.setSEQUENCE_TLV(cerInfoPkcsInfoUtil.pkcs7)
        val sigalg = PkcsInfoUtil()
        sigalg.setObjectIdentifier_TLV(byteArrayOf(42, -127, 28, -49, 85, 1, -125, 17))
        sigalg.setNull_TLV()
        signValuePkcsInfoUtil.setSEQUENCE_TLV(sigalg.pkcs7)
        val encodealgPkcsInfoUtil = PkcsInfoUtil()
        encodealgPkcsInfoUtil.setObjectIdentifier_TLV(byteArrayOf( 42, -127, 28, -49, 85, 1, -126, 45))
        encodealgPkcsInfoUtil.setNull_TLV()
        signValuePkcsInfoUtil.setSEQUENCE_TLV(encodealgPkcsInfoUtil.pkcs7)
        signValuePkcsInfoUtil.setOctetString_TLV(sig)
        signValuePkcsInfoUtil.packSEQUENCE_TLV()
        signedData.setSET_SET_OF_TLV(signValuePkcsInfoUtil.pkcs7)
        signedData.packSEQUENCE_TLV()
        val retPkcsInfoUtil = PkcsInfoUtil()
        retPkcsInfoUtil.setObjectIdentifier_TLV(byteArrayOf(42, -127, 28, -49, 85, 6, 1, 4, 2, 2))
        retPkcsInfoUtil.setContext_TLV(signedData.pkcs7)
        retPkcsInfoUtil.packSEQUENCE_TLV()
        return PkcsInfoUtil.encode(retPkcsInfoUtil.pkcs7!!)
        return PkcsInfoUtil.encode(retPkcsInfoUtil.pkcs7!!)
    }

    @JvmStatic
    fun longToBytes(num: Long): ByteArray {
        val bytes = ByteArray(8)
        for (i in 0..7) {
            bytes[i] = (0xFF and num.toInt() shr i * 8).toByte()
        }
        return bytes
    }

    @JvmStatic
    fun intToBytes(num: Int): ByteArray {
        val bytes = ByteArray(4)
        bytes[0] = (0xFF and (num shr 0)).toByte()
        bytes[1] = (0xFF and (num shr 8)).toByte()
        bytes[2] = (0xFF and (num shr 16)).toByte()
        bytes[3] = (0xFF and (num shr 24)).toByte()
        return bytes
    }

    @JvmStatic
    fun intToByte(num: Int): String {
        val bytes = ByteArray(1)
        bytes[0] = (0xFF and num).toByte()
        return showResult16Str(bytes)
    }

    @JvmStatic
    fun byteToInt(bytes: ByteArray): Int {
        var num = 0
        var temp = 0xFF and (bytes[0].toInt() shl 0)
        num = num or temp
        temp = 0xFF and (bytes[1].toInt() shl 8)
        num = num or temp
        temp = 0xFF and (bytes[2].toInt() shl 16)
        num = num or temp
        temp = 0xFF and (bytes[3].toInt() shl 24)
        num = num or temp
        return num
    }

    @JvmStatic
    fun byteConvert32Bytes(n: BigInteger?): ByteArray? {
        var tmpd = ByteArray(32)
        if (n == null) {
            return null
        }
        val nBytes = n.toByteArray()
        tmpd = when (nBytes.size) {
            33 -> {
                System.arraycopy(nBytes, 1, tmpd, 0, 32)
                tmpd
            }
            32 -> {
                nBytes
            }
            else -> {
                for (i in 0 until (32 - nBytes.size)) {
                    tmpd[i] = 0
                }
                System.arraycopy(nBytes,0, tmpd, (32 - nBytes.size), nBytes.size)
                tmpd
            }
        }
        return tmpd
    }

    /**
     * 处理数据，不足16字节后补00
     * @param hexData
     * @return
     */
    fun dealData00(hexData: ByteArray?): ByteArray? {
        if (hexData == null) {
            return null
        }
        val dataLen = hexData.size
        val result = ByteArray(16)
        if (dataLen > 16) {
            System.arraycopy(hexData, 0, result, 0, 16)
        } else {
            System.arraycopy(hexData, 0, result, 0, dataLen)
        }
        return result
    }

    /**
     * 处理证书颁发者和拥有者的信息
     * @param dn
     * @return
     */
    fun dealCertDN(dn: String): String {
        var dn = dn
        if (TextUtils.isEmpty(dn)) {
            return ""
        }
        val sbf = StringBuffer()
        sbf.append(dn.substring(0, 1))
        dn = dn.substring(1)
        val fm = arrayOf("C=", "CN=", "O=", "OU=")
        val fml = fm.size
        for (i in 0 until fml) {
            dn.replace(fm[i].toRegex(), "," + fm[i])
        }
        sbf.append(dn)
        return sbf.toString()
    }

    /**
     * @param cs
     * @return
     */
    fun charToByteArray(cs: CharArray): ByteArray {
        val csl = cs.size
        val bArray = ByteArray(csl)
        for (i in 0 until csl) {
            bArray[i] = (cs[i].code and 0x00FF) as Byte
        }
        return bArray
    }

    fun hex2String(input: ByteArray?): ByteArray {
        val s1 = bytesToHexStr(input)
        return s1!!.toByteArray()
    }

    /**
     * 在数据前补两字节的长度
     * @param s
     * @return
     */
    fun hexStr2LV00_2(s: String?): String {
        return if (s == null || "" == s) {
            "0000"
        } else (int2HexStr2(s.length / 2) + s)
    }

    /**
     * 获取一个16进制的字符串
     * @param l 随机数长度
     * @return Hex编码展开的字符串
     */
    fun getRandom(l: Int): String {
        var hexs = arrayOf("A", "B", "C", "D", "E", "F")
        val sbf = StringBuffer()
        var t = 0
        var st = ""
        val random = Random()
        for (i in 0 until 2 * l) {
            t = random.nextInt(16)
            st = if (t > 9) {
                hexs[t % 10]
            } else {
                "" + t
            }
            sbf.append(st)
        }
        return sbf.toString()
    }
}