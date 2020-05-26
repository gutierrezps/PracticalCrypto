<?php

/**
 * PHP decryption example for the PracticalCrypto library.
 * Version 0.1.0
 * https://github.com/gutierrezps/PracticalCrypto
 */


// the key must be 64-char long and must be the same used on encryption:
$cryptoKeys = '07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL';

// ciphertext
$ciphertext = '18CB4B32D8269490C9770AD74214D5DA33BFA0B32879D59BAE2348168083BBC39F1463D4CED259F9404A0EB79FDF4EB195024D02';


echo "Encryption key: $cryptoKeys\n";
echo "Ciphertext: '$ciphertext'\n";

$cryptMethod = 'aes-128-cbc';
$hashAlgo = 'sha1';

if (!in_array($cryptMethod, openssl_get_cipher_methods())) {
    throw new \Exception('Encryption method not found');
}

if (!in_array($hashAlgo, hash_hmac_algos())) {
    throw new \Exception('Hash algorithm not found');
}

if (strlen($ciphertext) < 104 || strlen($ciphertext) % 2 !== 0) {
    throw new \Exception('Wrong ciphertext length');
}

if (strlen($cryptoKeys) !== 64) {
    throw new \Exception('Wrong cryptoKeys length');
}

$staticIv = substr($cryptoKeys, 0, 16);
$ivKey = substr($cryptoKeys, 16, 16);
$dataKey = substr($cryptoKeys, 32, 16);
$hashKey = substr($cryptoKeys, 48, 16);

$ivEnd = 32;
$hashStart = strlen($ciphertext) - 40;

$ivCipher = hex2bin(substr($ciphertext, 0, $ivEnd));
$dataCipher = hex2bin(substr($ciphertext, $ivEnd, $hashStart - $ivEnd));
$hashExpected = hex2bin(substr($ciphertext, $hashStart));

$hashValue = hash_hmac($hashAlgo, $ivCipher.$dataCipher, $hashKey, $as_binary=true);

if (!hash_equals($hashExpected, $hashValue)) {
    throw new \Exception('Hash mismatch');
}

$iv = openssl_decrypt($ivCipher, $cryptMethod, $ivKey, $options=OPENSSL_RAW_DATA, $staticIv);
if (!$iv) {
    throw new \Exception('Failed to decode IV');
}

// 16th byte is set manually to match padding used to encrypt IV
$iv[15] = "\x1";

$plaintext = openssl_decrypt($dataCipher, $cryptMethod, $dataKey, $options=OPENSSL_RAW_DATA, $iv);

if (!$plaintext) {
    throw new \Exception('Failed to decode plaintext');
}

echo "Plaintext: '$plaintext'\n";