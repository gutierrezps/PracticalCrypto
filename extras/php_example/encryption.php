<?php

/**
 * PHP encryption example for the PracticalCrypto library.
 * Version 0.1.0
 * https://github.com/gutierrezps/PracticalCrypto
 */


// generates a valid key for the library
// 48 bytes are encoded as 64 chars in base64
$cryptoKeys = base64_encode(random_bytes(48));

// you can also set your own key, that must have 64 chars. here's an example:
// $cryptoKeys = '07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL';

// text to be encrypted
$plaintext = 'hello world!';


echo "Encryption key: $cryptoKeys\n";
echo "Plaintext: '$plaintext'\n";

$cryptMethod = 'aes-128-cbc';
$hashAlgo = 'sha1';

if (!in_array($cryptMethod, openssl_get_cipher_methods())) {
    throw new \Exception('Encryption method not found');
}

if (!in_array($hashAlgo, hash_hmac_algos())) {
    throw new \Exception('Hash algorithm not found');
}

if (strlen($cryptoKeys) !== 64) {
    throw new \Exception('Wrong cryptoKeys length');
}

$staticIv = substr($cryptoKeys, 0, 16);
$ivKey = substr($cryptoKeys, 16, 16);
$dataKey = substr($cryptoKeys, 32, 16);
$hashKey = substr($cryptoKeys, 48, 16);

// 12 bytes are encoded as 16 chars in base64
$iv = base64_encode(random_bytes(12));

// in order to encrypted IV be exactly 16-byte long, IV must have 15 bytes,
// and openssl_encrypt adds a 16th padding byte equals 0x01
$iv = substr($iv, 0, 15);

// encrypted IV (padding is added automatically)
$ivCipher = openssl_encrypt($iv, $cryptMethod, $ivKey, $options=OPENSSL_RAW_DATA, $staticIv);

// the 16th byte is now added manually in order to encrypt the plaintext correctly
$iv[15] = "\x1";

// encrypted plaintext
$dataCipher = openssl_encrypt($plaintext, $cryptMethod, $dataKey, $options=OPENSSL_RAW_DATA, $iv);

// Encrypt-then-MAC: hash is calculated from ivCipher and dataCipher concatenated
$hash = hash_hmac($hashAlgo, $ivCipher.$dataCipher, $hashKey, $as_binary=true);

echo "Ciphertext: '" . bin2hex($ivCipher) . bin2hex($dataCipher) . bin2hex($hash) . "'\n";