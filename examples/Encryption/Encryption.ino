/**
 * @file Encryption.ino
 * @author Gutierrez PS (https://github.com/gutierrezps)
 * @brief Encryption example using PracticalCrypto library
 * @version 0.1.0
 * @date 2020-05-25
 * 
 */

#include <Arduino.h>
#include <PracticalCrypto.h>

PracticalCrypto crypto;

void setup()
{
    Serial.begin(9600);

    // generates a valid key for the library
    String key = crypto.generateKey();

    // you can also set your own key, that must have 64 chars. here's an example:
    // String key = "07BN(%$*Xs-`9YKjRIv=5[a&HTn3s%@@OnKFPBjh`d=]t#wH)qDOW9yWW+fZT1xL";

    crypto.setKey(key);
    
    // let's make sure the key was set.
    // if the key is empty, it's likely your key doesn't have the right length
    key = crypto.getKey();
    Serial.printf("\nEncryption key: %s\n", key.c_str());


    String plaintext = "hello world!";
    Serial.printf("Plaintext: '%s'\n", plaintext.c_str());

    String ciphertext = crypto.encrypt(plaintext);

    if (ciphertext.length() == 0) {
        Serial.printf("Encryption failed (status %d)\n", crypto.lastStatus());
        while (1) yield();
    }

    Serial.printf("Ciphertext: '%s'\n", ciphertext.c_str());
}

void loop()
{
    // ...
}