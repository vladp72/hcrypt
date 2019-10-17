# C++ Helper Classes for Windows Cryptography API Next Generation (CNG), that includes BCRYPT and NCRYPT.

This is a header only library for Windows CNG API that includes functions from ncrypt.h and bcrypt.h.

[MSDN documentation for bcrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/)

[CNG Bcrypt algorithm providers](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cng-cryptographic-algorithm-providers)

[CNG algorithm identifiers](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers) 

[MSDN documentation for ncrypt.h](https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/)

[CNG Ncrypt storage providers](https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers) 

[MSDN CNG samples](https://docs.microsoft.com/en-us/windows/win32/seccng/typical-cng-programming?redirectedfrom=MSDN)

[MSDN classic samples](https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Security)

[StackOverflow threads with cng tag](https://stackoverflow.com/questions/tagged/cng)

*Note: CNG bcrypt does not implement Blowfish algorithm. CNG bcrypt originated from BestCrypt. [See this discussion for more details](https://stackoverflow.com/questions/9711568/does-winapis-bcrypt-h-actually-support-bcrypt-hashing)*

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

*Note: In all classes you will find each crypto function wrapperd twice. One wrapper will have "try_" prefix and will be noexcept. It will communicate failure by returning std::error_code. The other wrapper will not have 'try' prefix and will communicate most failures using an exception. For example:*
 
 ```
 class storage_provider {
 public:
   //
   // This wrapped would not throw exception.
   // It communicates failure using std::error_code
   //
   [[nodiscard]] std::error_code try_open(wchar_t const *provider) noexcept;
   //
   // This wrapper communicates failures using exception
   //
   void open(wchar_t const *provider)
 };
 ```
*Use try_ wrappers in the performance critical code when failures are expected to happen often and can affect performance. It is also a good fit when you need to use wrappers in an exception unsafe code base.*

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
    
  bcrypt::key k{ap.generate_symmetric_key(reinterpret_cast<char const *>(key), 32)};
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
## Hashing Data

```
   try {
       hcrypt::buffer data_to_hash;
       data_to_hash.resize(150);
       bcrypt::generate_random(data_to_hash.data(), data_to_hash.size());
   
       bcrypt::algorithm_provider provider{BCRYPT_SHA256_ALGORITHM};
       bcrypt::hash h{provider.create_hash()};
       h.hash_data(data_to_hash.data(), data_to_hash.size());
       hcrypt::buffer hash_value{h.finish()};
       printf("hash: %ws\n", hcrypt::to_hex(hash_value).c_str());
   } catch (std::system_error const &ex) {
       <handle failure>
   }
```

## Signing Data Using Symmetric Key

```
    unsigned char const key[] = {
        0x1b, 0x20, 0x5a, 0x9e, 0x2b, 0xe3, 0xfe, 0x85, 0x9c, 0x37, 0xf1,
        0xaf, 0xfe, 0x81, 0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81,
        0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81, 0x88, 0x92,
    };

    try {
        bcrypt::algorithm_provider ap{BCRYPT_AES_ALGORITHM};
        ap.set_chaining_mode(BCRYPT_CHAIN_MODE_CCM);

        bcrypt::key k{ap.generate_symmetric_key(
                      reinterpret_cast<char const *>(key), 
                      32)};
  
        // The data to be GMAC'd. It is not encrypted.
        std::string_view aad(
            "Not so secret additionally authenticated data");

        UCHAR iv[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc};
        UCHAR tag[16] = {0};

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aadInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(aadInfo);
        aadInfo.pbNonce = iv;
        aadInfo.cbNonce = sizeof(iv);
        aadInfo.pbAuthData = reinterpret_cast<UCHAR *>(const_cast<char *>(&aad[0]));
        aadInfo.cbAuthData = static_cast<ULONG>(aad.size());
        aadInfo.cbAAD = static_cast<ULONG>(aad.size());
        aadInfo.pbTag = tag;
        aadInfo.cbTag = sizeof(tag);

        size_t bytes_written{0};
        k.encrypt(nullptr, 0, &aadInfo, nullptr, 0, nullptr, 0, &bytes_written);

        printf("Hash %S\n", hcrypt::to_hex(std::begin(tag), std::end(tag)).c_str());        

    } catch (std::system_error const &ex) {
        <handle error>
    }

```

## Encrypting and Signing Using Symmetric Key

```
    unsigned char const plain_text[] = "Text1 to encrypt";

    unsigned char const iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    unsigned char const key128[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

     try {
         bcrypt::algorithm_provider ap{BCRYPT_AES_ALGORITHM};
         ap.set_chaining_mode(BCRYPT_CHAIN_MODE_CBC);

         size_t block_length{ap.get_block_length()};

         hcrypt::buffer iv_buffer{std::begin(iv), std::begin(iv) + block_length};

         bcrypt::key k_a{ap.generate_symmetric_key(reinterpret_cast<char const *>(key128), 16)};
         
         hcrypt::buffer exported_key{k_a.export_key(BCRYPT_OPAQUE_KEY_BLOB)};

         size_t data_size{sizeof(plain_text)};
         size_t block_size{ap.get_block_length()};
         size_t padded_size{hcrypt::round_to_block(data_size, block_size)};
         hcrypt::buffer data_buffer(padded_size);
         std::copy(std::begin(plain_text), std::end(plain_text), std::begin(data_buffer));

         size_t bytes_encrypted{0};

         //
         // AES is a block algorithm, and BCRYPT_BLOCK_PADDING
         // tells it that this is last block that might not be
         // block alligned, and have to be padded
         //

         k_a.encrypt(data_buffer.data(),
                     data_size,
                     nullptr,
                     iv_buffer.data(),
                     iv_buffer.size(),
                     data_buffer.data(),
                     data_buffer.size(),
                     &bytes_encrypted,
                     BCRYPT_BLOCK_PADDING);

         bcrypt::key k_b{ap.import_symetric_key(nullptr,
                                                BCRYPT_OPAQUE_KEY_BLOB,
                                                exported_key.data(),
                                                exported_key.size())};

         iv_buffer.assign(std::begin(iv), std::begin(iv) + block_length);

         size_t bytes_decrypted{0};

         if (k_b.decrypt(data_buffer.data(),
                         data_buffer.size(),
                         nullptr,
                         iv_buffer.data(),
                         iv_buffer.size(),
                         data_buffer.data(),
                         data_buffer.size(),
                         &bytes_decrypted,
                         BCRYPT_BLOCK_PADDING)) {
              
             <decryption succeeded>
         } else {
             <decryption failed>
         }

     } catch (std::system_error const &ex) {
         <handle error>;
     }
```

## Signing Using Persistent Assymetric Sample

```
   unsigned char const msg[] = {
       0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6, 0xe3, 0x62, 0x6f, 0x1a,
       0x55, 0xe2, 0xaf, 0x5e, 0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
   };

   try {
       bcrypt::algorithm_provider hash_ap{BCRYPT_SHA256_ALGORITHM};
       //
       // Hash message
       //       
       bcrypt::hash h{hash_ap.create_hash()};
       h.hash_data(reinterpret_cast<char const *>(msg), sizeof(msg));
       hcrypt::buffer data_hash{h.finish()};
       //
       // Generate persistent keys for signing
       //       
       ncrypt::storage_provider sp{MS_KEY_STORAGE_PROVIDER};
       ncrypt::key k{sp.create_key(NCRYPT_ECDSA_P256_ALGORITHM, 
                                   L"test_key_name_ecdsa_F3686E9E-A097-4959-A014-D8D2B2D9F42F")};
       k.finalize_key();
       //
       // Sign hash
       //       
       hcrypt::buffer hash_signature{
           k.sign_hash(data_hash.data(), data_hash.size())};
       //
       // Export public key
       //                  
       hcrypt::buffer exported_public_key{k.export_key(BCRYPT_ECCPUBLIC_BLOB)};
       //
       // Import public key
       //              
       bcrypt::algorithm_provider signing_ap{BCRYPT_ECDSA_P256_ALGORITHM};
       bcrypt::key public_key{
           signing_ap.import_key_pair(BCRYPT_ECCPUBLIC_BLOB,
                                      exported_public_key.data(),
                                      exported_public_key.size())};
       //
       // Verify signature signing
       //       
       BCRYPT_CODDING_ERROR_IF_NOT(
           public_key.verify_signature(nullptr,
                                       data_hash.data(),
                                       data_hash.size(),
                                       hash_signature.data(),
                                       hash_signature.size()));
   } catch (std::system_error const &ex) {
       <handle failure>
   }
```

## Class Diagrams

*Note: CRTP in the diagrams stands for [Curiously recurring template pattern](https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern)*

### All Modules
![Class Diagram; All together](/doc/all_d.png)

### hbcrypt.h
![Class Diagram; bcrypt only](/doc/bcrypt_d.png)

### hncrypt.h
![Class Diagram; ncrypt only](/doc/ncrypt_d.png)

### hcrypt.h
![Class Diagram; hcrypt only](/doc/hcrypt_d.png)

