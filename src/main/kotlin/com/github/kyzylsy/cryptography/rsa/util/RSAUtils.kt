package com.github.kyzylsy.cryptography.rsa.util

import com.github.kyzylsy.cryptography.rsa.constant.RSAAlgorithm
import com.github.kyzylsy.cryptography.rsa.constant.RSAKeySize
import com.github.kyzylsy.cryptography.rsa.model.RSAKeyPair
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * @author LSteven
 * @date 2018/5/16 下午4:41.
 */
class RSAUtils {

    companion object {

        private const val cryptosystem = "RSA"

        fun generateKsKeyPair(keySize: RSAKeySize): RSAKeyPair {
            val instance = KeyPairGenerator.getInstance(cryptosystem)
            instance.initialize(keySize.size)
            val kp = instance.generateKeyPair()

            val x509EncodedKeySpec = X509EncodedKeySpec(kp.public.encoded)
            var kf = KeyFactory.getInstance(cryptosystem)
            val publicKey = kf.generatePublic(x509EncodedKeySpec)

            val pkcs8EncodedKeySpec = PKCS8EncodedKeySpec(kp.private.encoded)
            kf = KeyFactory.getInstance(cryptosystem)
            val privateKey = kf.generatePrivate(pkcs8EncodedKeySpec)

            return RSAKeyPair(publicKey, privateKey)
        }

        /**
         * 用私钥对信息生成数字签名
         */
        fun sign(data: ByteArray, privateKey: String, specificAlgorithm: RSAAlgorithm): ByteArray {
            val pkcs8EncodedKeySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey))
            val kf = KeyFactory.getInstance(cryptosystem)
            val generatePrivate = kf.generatePrivate(pkcs8EncodedKeySpec)

            val instance = Signature.getInstance(specificAlgorithm.name)
            instance.initSign(generatePrivate)
            instance.update(data)
            return instance.sign()
        }

        /**
         * 校验数字签名
         */
        fun verifySign(data: ByteArray,
                       publicKey: String,
                       sign: String,
                       specificAlgorithm: RSAAlgorithm): Boolean {
            val x509EncodedKeySpec = X509EncodedKeySpec(Base64.getDecoder().decode(publicKey))
            val kf = KeyFactory.getInstance(cryptosystem)
            val generatePublic = kf.generatePublic(x509EncodedKeySpec)

            val instance = Signature.getInstance(specificAlgorithm.name)
            instance.initVerify(generatePublic)
            instance.update(data)

            return instance.verify(Base64.getDecoder().decode(sign))
        }
    }
}