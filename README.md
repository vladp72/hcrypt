# C++ Helper Classes for Windows CNG BCRYPT and NCRYPT APIs.

[MSDN Documentation for bcrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/)

[MSDN Documentation for ncrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/)

[CNG Samples](https://docs.microsoft.com/en-us/windows/win32/seccng/typical-cng-programming?redirectedfrom=MSDN)

[This post](https://stackoverflow.com/questions/40596395/cng-when-to-use-bcrypt-vs-ncrypt-family-of-functions) by dbush provides a good summary when to use NCrypt API versus BCrypt API.

The BCrypt family of function are classified as Cryptographic Primitives, while the NCrypt family of functions are classified as Key Storage and Retrieval.

The primary difference is that the BCrypt functions are used when dealing only with ephemeral keys, while the NCrypt functions are used when persistent keys are required. 

In practice, the BCrypt functions are typically used for hashing and symmetric encryption, while the NCrypt functions are used for public/private key encryption and decryption, public/private key signing and verification, and shared secret (e.g. DH and ECDH) negotiation. 

While some public/private key operations can be done with BCrypt functions, they can only be used with ephemeral keys and are therefore of limited use.

Persistent keys are stored in key containers specific to each user (or to the system). This is a security measure to ensure that users can't view each other's private keys.

In general, you'll want to use the following functions for the following operations:
* BCryptHashData: Used for hashing and HMAC (MD5, SHA1, SHA256, SHA384, SHA512) 
  * Related: BCryptCreateHash, BCryptFinishHash, BCryptDestroyHash
* BCryptEncrypt: Symmetric key encryption (DES, 3DES, AES). 
  * Related: BCryptGenerateSymmetricKey, BCryptDestroyKey
* BCryptDecrypt: Symmetric key decryption (DES, 3DES, AES). 
  * Related: BCryptGenerateSymmetricKey, BCryptDestroyKey
* NCryptEncrypt: Asymmetric key encryption (RSA)
* NCryptDecrypt: Asymmetric key decryption (RSA)
* NCryptSignHash: Asymetric key signature (RSA, DSA, ECDSA)
* NCryptVerifySignature: Asymmetric key signature verification (RSA, DSA, ECDSA)
* NCryptSecretAgreement: Asymmetric key secret sharing (DH, ECDH) 
* Related: NCryptDeriveKey

Helper classes consists of several namespaces:

1. **hcrypt** helper function and error category definitions. These helpers are shared between bcrypt and ncrypt.
1. **bcrypt** helpers for functions in bcrypt.h
   1. **algorith_provider** instance of algorithm provider
   1. **key** implementation of shared/private/public key algorithm by a provider
   1. **hash** particular implementation of hash algorithm by a provider
   1. **secret** helper class for derivation of a key from a secret agreement.
1. **ncrypt** helpers for functions in ncrypt.h
   1. **storate_provider** instance of storage provider
   1. **storage_provider::key_iterator** enumiration of keys in the storage
   1. **key** implementation of shared/private/public key algorithm by a provider
   1. **secret** helper class for derivation of a key from a secret agreement.

*Note: ncrypt::property_impl and bcrypt::property_impl implement query/set property interfaces for all opbects in the namespace. Often times it is hard to tell from the MSDN documentation what property is applicable to what object type (key/hash/provide/sectret). A you cah [useprint_bcrypt_object_properties](https://github.com/vladp72/hcrypt/blob/master/test/hcrypt_test_helpers.hpp) and [print_ncrypt_object_properties](https://github.com/vladp72/hcrypt/blob/master/test/hcrypt_test_helpers.hpp) to create a test program that attempts to print every property for a passed object, and see what queries are supported for the given object.*

For example following snippet
```
  bcrypt::algorithm_provider ap{BCRYPT_AES_ALGORITHM};
  print_bcrypt_object_properties(2, ap, true);
```

  will print

```
      name: AES
      block length: 16
      chaining mode: ChainingModeCBC
      block[00] size: 16
      block[01] size: 4261281277
      keys length: min 128, max 256, increment 64
      key object length: 654
      message block length: 16
      object length: 654

```

After changing mode to CCM

```
  ap.set_chaining_mode(BCRYPT_CHAIN_MODE_CCM);
  print_bcrypt_object_properties(2, ap, true);
```

  you will get

```
      name: AES
      block length: 16
      chaining mode: ChainingModeCCM
      block[00] size: 16
      block[01] size: 4261281277
      keys length: min 128, max 256, increment 64
      key object length: 654
      auth tag length: min 4, max 16, increment 2
      message block length: 1
      object length: 654
```

  We can create kleys and print its properties
  
```
   unsigned char const key[] = {
        0x1b, 0x20, 0x5a, 0x9e, 0x2b, 0xe3, 0xfe, 0x85, 0x9c, 0x37, 0xf1,
        0xaf, 0xfe, 0x81, 0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81,
        0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81, 0x88, 0x92,
    };
    
  bcrypt::key k{ap.generate_symmetric_key(
  reinterpret_cast<char const *>(key), 32)};
  print_bcrypt_object_properties(2, k, true);
```

  output will be

```
      name: AES
      block length: 16
      chaining mode: ChainingModeCCM
      initialization vector: 00000000000000000000000000000000
      key length: 256
      key strength: 256
      message block length: 1
```
**Following class diagrams provide a quick summary of what objects and helpers you can find in the libarary**

*Note: CRTP in the diagrams stands for [Curiously recurring template pattern](https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern)*

![Class Diagram; Classes only](/doc/bcrypt_short.png)

![Class Diagram; Classes with Methods](/doc/bcrypt.png)
