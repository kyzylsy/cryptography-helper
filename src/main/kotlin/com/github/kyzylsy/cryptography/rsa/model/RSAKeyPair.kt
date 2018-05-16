package com.github.kyzylsy.cryptography.rsa.model

import java.security.PrivateKey
import java.security.PublicKey
import java.util.*

/**
 * @author LSteven
 * @date 2018/5/16 下午4:15.
 */
class RSAKeyPair constructor(val publicKey: PublicKey,
                             val privateKey: PrivateKey) {

    fun binaryPublicKey() = publicKey.encoded
    fun binaryPrivateKey() = privateKey.encoded

    fun stringPublicKey() = Base64.getEncoder().encodeToString(binaryPublicKey())
    fun stringPrivateKey() = Base64.getEncoder().encodeToString(binaryPrivateKey())
}