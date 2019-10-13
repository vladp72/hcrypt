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

![Class Diagram; Classes only](/doc/bcrypt_short.png)

![Class Diagram; Classes with Methods](/doc/bcrypt.png) 
