fun decrypt(strToDecrypt : String, passphrase: String) : String? {

    try {
        val salt_len = 16;
        val iv_len = 16;

        val encrypted = base64ToByteArray(strToDecrypt)

        val salt = encrypted.copyOfRange(0, salt_len);

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, 100_000, 256)
        val tmp = factory.generateSecret(spec);
        val key = SecretKeySpec(tmp.encoded, "AES")
        val iv = encrypted.copyOfRange(0 + salt_len, salt_len + iv_len);

        val cipherInstance = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipherInstance.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        val decipher =
            cipherInstance.doFinal(encrypted.copyOfRange(salt_len + iv_len, encrypted.size))


        return decipher.toString(Charset.defaultCharset())
    } catch (e: Exception) {
        println("Error while decrypting: $e");
    }
    return null
}

fun base64ToByteArray(base64Text: String): ByteArray {
    return Base64.decode(base64Text, Base64.DEFAULT)
}
