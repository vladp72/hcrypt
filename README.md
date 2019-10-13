# C++ Helper Classes for Windows CNG BCRYPT and NCRYPT APIs.

This is a header only library for Windows CNG API that includes functions from ncrypt.h and bcrypt.h.

[MSDN Documentation for bcrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/)

[MSDN Documentation for ncrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/)

[MSDN CNG Samples](https://docs.microsoft.com/en-us/windows/win32/seccng/typical-cng-programming?redirectedfrom=MSDN)

[Also check test and samples that come with this library](https://github.com/vladp72/hcrypt/tree/master/test)

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
   1. String Formatting
      1. **v_make_string** estimates string size using _vscprintf, resizes buffer and  prints string using _vsnprintf_s
      1. **make_string** calls v_make_string
      1. **v_make_wstring** estimates string size using _vscwprintf, resizes buffer and  prints string using _vsnwprintf_s
      1. **make_wstring** calls v_make_wstring
   1. **try_resize** family of functions that can be used in noexcept context to convert std::bad_alloc to an error code
   1. Convertion between character encodings
      1. **a_to_u** Converts multibype string to Unicode string
      1. **u_to_a** Converts  Unicode string to multibype string
   1. Error handling helpers for NTSTATUS and WIn32 error
      1. **enum class status : long** Enumeration type used for NTSTATUS
      1. **enum class win32_error : unsigned long** Enumeration type used for WIN32 erors domain
      1. **is_success** Family of functions that return true if error code is success
      1. **is_failure** Family of functions that return true if error code is a failure
      1. **error_category_t** error category for NTSTATUS
      1. **get_error_category** returns instance of errror_category_t
      1. **make_error_code** creates error_code with matching error category for the given enumeration type.
   1. Bitfield anumeration
      1. **set_flag** Sets bits
      1. **is_flag_on** Checks if bits are set
      1. **clear_flag** Clears bits
      1. **consume_flag** Clears bits and returns if they were set
   1. Conversion between bag of bytes and hexidecimal string
      1. **to_hex**
      1. **from_hex**
   1. Conversion between bag of bytes and base64 encoding string
      1. **to_base64**
      1. **from_base64**
   1. Time helper function
      1. **systemtime_to_filetime**
      1. **filetime_to_systemtime**
      1. **systemtime_to_string**
      1. **systemtime_to_wstring**
      1. **filetime_to_string**
      1. **filetime_to_wstring**
   1. GUID helper function
      1. **guid_to_string**
      1. **guid_to_wstring**
   1. Other
      1. **round_to_block** rounds up size to number of blocks of specified size.         
1. **bcrypt** helpers for functions in bcrypt.h
   1. **algorith_provider** instance of algorithm provider. You can enumerate providers using **try_enum_registered_providers**, **enum_registered_providers**, **try_resolve_providers**, **resolve_providers**, **try_enum_algorithms** or **enum_algorithms**. To navigate result of enumeration prefer to use bcrypt::for_each or bcrypt::find_first family of functions.
   1. **key** implementation of shared/private/public key algorithm by a provider
   1. **hash** particular implementation of hash algorithm by a provider
   1. **secret** helper class for derivation of a key from a secret agreement. To create secret you can use *bcrypt::create_secret* helper function
1. **ncrypt** helpers for functions in ncrypt.h
   1. **storate_provider** instance of storage provider. You can enumerate providers using **try_enum_providers** or **enum_providers**. To navigate result of enumeration prefer to use ncrypt::for_each or ncrypt::find_first family of functions.
   1. **storage_provider::key_iterator** enumeration of keys in the storage
   1. **key** implementation of shared/private/public key algorithm by a provider
   1. **secret** helper class for derivation of a key from a secret agreement. To create secret you can use *ncrypt::create_secret* helper function

*Note: ncrypt::property_impl and bcrypt::property_impl implement query/set property interfaces for all obects in each namespace. Often times it is hard to tell from the MSDN documentation what property is applicable to what object type (key/hash/particular provide/secret). You can use [useprint_bcrypt_object_properties](https://github.com/vladp72/hcrypt/blob/master/test/hcrypt_test_helpers.hpp) and [print_ncrypt_object_properties](https://github.com/vladp72/hcrypt/blob/master/test/hcrypt_test_helpers.hpp) to create a test program that attempts to print every property for a passed object, and see what queries are supported for the given object.*

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
