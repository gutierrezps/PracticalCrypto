/**
 * Node.js decryption example for the PracticalCrypto library.
 * Version 0.1.0
 * https://github.com/gutierrezps/PracticalCrypto
 */

const crypto = require('crypto');

const ciphertext = '18CB4B32D8269490C9770AD74214D5DA33BFA0B32879D59BAE2348168083BBC39F1463D4CED259F9404A0EB79FDF4EB195024D02';
const key = '07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL';

const cryptoAlgorithm = 'aes-128-cbc';
const hashAlgorithm = 'sha1';

if (key.length !== 64) {
    throw 'Invalid key length';
}

if (ciphertext.length < 104 || ciphertext.length % 2 !== 0) {
    throw 'Wrong ciphertext length';
}

const staticIv = key.substring(0, 16);
const ivKey = key.substring(16, 32);
const dataKey = key.substring(32, 48);
const hashKey = key.substring(48, 64);

const cipherLen = ciphertext.length;
const ivCipher = Buffer.from(ciphertext.substring(0, 32), 'hex');
const dataCipher = Buffer.from(ciphertext.substring(32, cipherLen-40), 'hex');
const hashExpected = Buffer.from(ciphertext.substring(cipherLen-40), 'hex');

const hashCrypto = crypto.createHmac(hashAlgorithm, hashKey);
hashCrypto.update(ivCipher);
hashCrypto.update(dataCipher);
const hashCalculated = hashCrypto.digest();

if (!hashCalculated.equals(hashExpected)) {
    throw 'Hash mismatch';
}

const ivCrypto = crypto.createDecipheriv(cryptoAlgorithm, ivKey, staticIv)
ivCrypto.update(ivCipher);
let iv = ivCrypto.final();

iv = Buffer.concat([iv, Buffer.alloc(1, 1)], 16);

const dataCrypto = crypto.createDecipheriv(cryptoAlgorithm, dataKey, iv);
dataCrypto.update(dataCipher);
let plaintext = dataCrypto.final('utf8');

console.log(plaintext);