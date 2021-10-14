package com.froad.sm2testpro.test

import com.froad.sm2testpro.utils.FCharUtils.bytesToHexStr
import com.froad.sm2testpro.utils.FCharUtils.hexString2ByteArray
import com.froad.sm2testpro.utils.SM2Util
import org.bc.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECGenParameterSpec

class SM2Test {
    companion object {
        fun creatKeys () : Array<String>? {

//            创建SM2密钥对
            try {
                println("----------生成秘钥对start----------------")
                // 引入BC库
                Security.addProvider(BouncyCastleProvider())
                // 获取SM2椭圆曲线的参数
                val sm2Spec = ECGenParameterSpec("sm2p256v1")
                // 获取一个椭圆曲线类型的密钥对生成器
                val kpg: KeyPairGenerator =
                    KeyPairGenerator.getInstance("EC", BouncyCastleProvider())
                // 使用SM2的算法区域初始化密钥生成器
                kpg.initialize(sm2Spec, SecureRandom())
                // 获取密钥对
                val keyPair = kpg.generateKeyPair()
                val pk = keyPair.public
                val privk = keyPair.private
                val pkRes = bytesToHexStr(pk.encoded)
                val priKRes = bytesToHexStr(privk.encoded)
                if (pkRes == null || priKRes == null) {
                    return null
                }
                println("----------生成秘钥对end----------------")
                return arrayOf(pkRes, priKRes)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: InvalidAlgorithmParameterException) {
                e.printStackTrace()
            }
            return null
        }
    }
}

fun main (args : Array<String>) {
    //测试方法
//    runBlocking {
//        println("main>>>ThreadName>>>${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        //不阻塞进程
//        launch (Dispatchers.IO){
//            println("launch1>>>IO>>>ThreadName>>>${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//            var keys : Array<String>? = SM2Test.creatKeys()
//            if (keys == null) {
//                println("SM2密钥对创建失败")
//            } else {
//                println("publicKey:${keys[0]}")
//                println("privateKey:${keys[1]}")
//            }
//        }
//        launch (Dispatchers.IO){
//            println("launch2>>>IO>>>ThreadName>>>${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        }
//        println("launchResult end")
//
//        //withContext是串行执行，会阻塞后续进程执行
//        val withContextResult1 = withContext(Dispatchers.IO) {
//            delay(2000)
//            println( "1协程执行—${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        }
//        val withContextResult2 = withContext(Dispatchers.IO) {
//            delay(1000)
//            println( "2协程执行— ${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        }
//        println("withContextresult $withContextResult1 $withContextResult2")
//
//
//        //async是并行执行，可以通过awiat函数锁定获取结果
//        val asyncResult1 = async(Dispatchers.IO) {
//            delay(2000)
//            println("1协程执行—${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        }
//        val asyncResult2 = async(Dispatchers.IO) {
//            delay(1000)
//            println("2协程执行— ${Thread.currentThread().name}_id_${Thread.currentThread().id}")
//        }
//        println("asyncResult ${asyncResult1.await()} ${asyncResult2.await()}")
//        println("asyncResult end")
//
//    }

    val sm2PubKey =
        "C549D206235CB6A6416D3AD8A297A205064E7DA02728214C5F9B130D2F7D82023BBE4992C2D2AAC7929B7C49B67EEF9E40C0B584A66B1C145FCA17F290B1845B"
    val sm2PriKey = "7E3368AFDACEDCBEA68DF63EE81713ED339D84DB29AF0B2752578823D610A6E2"
    val sourceData = "1DAC040AA8EC1D6FF6F2782BADDB491517899B80D65B6E80F368E3AFAC16"
    val sm2EncData = bytesToHexStr(
        SM2Util.encrypt(
            hexString2ByteArray(sm2PubKey),
            hexString2ByteArray(sourceData),
            false,
            1
        )
    )
    println("sm2EncData:$sm2EncData")
    val sm2DecData = bytesToHexStr(
        SM2Util.decrypt(
            hexString2ByteArray(sm2PriKey),
            hexString2ByteArray(sm2EncData!!),
            false,
            1
        )
    )
    println("sm2DecData:$sm2DecData")
}