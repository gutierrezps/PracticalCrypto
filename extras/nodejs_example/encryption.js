/**
 * Node.js encryption example for the PracticalCrypto library.
 * Version 0.1.0
 * https://github.com/gutierrezps/PracticalCrypto
 */

const crypto = require('crypto');

const plaintext = 'hello world!';
const key = '07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL';

const cryptoAlgorithm = 'aes-128-cbc';
const hashAlgorithm = 'sha1';

if (key.length !== 64) {
    throw 'Invalid key length';
}

const staticIv = key.substring(0, 16);
const ivKey = key.substring(16, 32);
const dataKey = key.substring(32, 48);
const hashKey = key.substring(48, 64);


// 16th byte is added as padding on inCrypto
let iv = crypto.randomBytes(15);

const ivCrypto = crypto.createCipheriv(cryptoAlgorithm, ivKey, staticIv)
ivCrypto.update(iv);
let ivCipher = ivCrypto.final();

// now adding 16th byte for data encryption
iv = Buffer.concat([iv, Buffer.alloc(1, 1)], 16);

const dataCrypto = crypto.createCipheriv(cryptoAlgorithm, dataKey, iv);
dataCrypto.update(plaintext);
let dataCipher = dataCrypto.final();

const hash = crypto.createHmac(hashAlgorithm, hashKey);
hash.update(ivCipher);
hash.update(dataCipher);

const ciphertext = ivCipher.toString('hex') + dataCipher.toString('hex') + hash.digest('hex');

console.log(ciphertext);