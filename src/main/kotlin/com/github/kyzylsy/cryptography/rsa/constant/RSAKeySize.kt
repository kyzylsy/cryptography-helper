package com.github.kyzylsy.cryptography.rsa.constant

/**
 * @author LSteven
 * @date 2018/5/16 下午4:48.
 */
enum class RSAKeySize(val size: Int) {
    KEY_SIZE_1024(1024),
    KEY_SIZE_2048(2048),
    KEY_SIZE_4096(4096)
}