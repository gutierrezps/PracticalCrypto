# PracticalCrypto

A simple library to encrypt and decrypt strings with hashing, for ESP8266, based
on [BearSSL](bearssl.org/) library that is already available on the ESP8266
Arduino core.

Based on "[Practical IoT Cryptography On The Espressif ESP8266](https://hackaday.com/2017/06/20/practical-iot-cryptography-on-the-espressif-esp8266/)",
by Sean Boyce on Hackaday, published at June 20, 2017.

Implementation details of this library are shown at <https://gutierrezps.wordpress.com/2020/05/25/practical-iot-cryptography-on-the-esp8266-using-arduino/>.

## Features

* Simple usage, only three main methods can be used
* String inputs and outputs
* Encryption key generation

## Examples

The `examples` folder contains library examples for Arduino. The `extras` folder
contains examples for PHP (run with `php <example>.php`) and NodeJS
(run with `nodejs <example>.js`).

## API

* `bool setKey(String key)` - Set an encryption key (exactly
64 char long), Returns true if key was set sucessfully set.
* `String getKey()` - Returns the key currently set.
* `String generateKey()` - Generates a random 64-char long
encryption key.
* `String encrypt(String plaintext)` - Encrypts the given
plaintext with the key set previously. Returns the ciphertext
encoded as an hex string.
* `String decrypt(String ciphertext)` - Decrypts the given
ciphertext hex string with the key set previously. Returns
the original plaintext.
* `uint16_t hexStringToArray(String input, uint8_t *output, uint16_t capacity)` -
    Converts an hex string to a byte array.
* `String arrayToHexString(uint8_t *input, uint16_t len)` - Converts a byte
    array to an hex string.
* `PracticalCrypto::Status lastStatus()` - If something went wrong while
    encrypting, decrypting or converting from hex to binary, `lastStatus()` will
    indicate what went wrong.
