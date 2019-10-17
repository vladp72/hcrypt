#include "hbcrypt_test_message_signing.hpp"
#include <algorithm>

namespace {

    // wchar_t const *hash_algorithms[]{
    //    // BCRYPT_MD2_ALGORITHM,
    //    // BCRYPT_MD4_ALGORITHM,
    //    // BCRYPT_MD5_ALGORITHM,
    //    BCRYPT_SHA1_ALGORITHM,
    //    // BCRYPT_SHA256_ALGORITHM,
    //    // BCRYPT_SHA384_ALGORITHM,
    //    // BCRYPT_SHA512_ALGORITHM,
    //};

    // wchar_t const *encryption_algorithms[]{
    //    BCRYPT_DSA_ALGORITHM,
    //    /*  BCRYPT_AES_ALGORITHM,
    //        BCRYPT_AES_GMAC_ALGORITHM,
    //        BCRYPT_AES_CMAC_ALGORITHM,
    //        BCRYPT_ECDSA_P256_ALGORITHM,
    //        BCRYPT_ECDSA_P384_ALGORITHM,
    //        BCRYPT_ECDSA_P521_ALGORITHM,
    //        BCRYPT_ECDH_P256_ALGORITHM,
    //        BCRYPT_ECDH_P384_ALGORITHM,
    //        BCRYPT_ECDH_P521_ALGORITHM,*/
    //};

    struct test_signing_algorithm_t {
        wchar_t const *hashing_algorithm;
        wchar_t const *encryption_algorithm;
        size_t encription_key_length;
    };

    test_signing_algorithm_t test_signing_algorithms[]{
        {BCRYPT_SHA1_ALGORITHM, BCRYPT_DSA_ALGORITHM, 1024},
    };

    void test_message_signing(int offset,
                              wchar_t const *hash_algorithm_name,
                              wchar_t const *encryption_algorithm_name,
                              size_t encryption_key_length,
                              hcrypt::buffer const &data_to_sign) {
        try {
            printf("\n%*c-| Hash algorithm %S, encryption algorithm %S, key "
                   "length %Iu |-\n",
                   offset,
                   ' ',
                   hash_algorithm_name,
                   encryption_algorithm_name,
                   encryption_key_length);

            offset += 2;

            printf("\n%*cOpening hash algorithm %S.\n", offset, ' ', hash_algorithm_name);

            bcrypt::algorithm_provider hash_provider{hash_algorithm_name};
            print_bcrypt_object_properties(offset + 2, hash_provider, true);

            printf("%*cCreating hash object.\n", offset, ' ');

            bcrypt::hash h{hash_provider.create_hash()};
            print_bcrypt_object_properties(offset + 2, h, true);

            printf("\n%*cOpening encryption algorithm %S.\n", offset, ' ', encryption_algorithm_name);

            bcrypt::algorithm_provider encryption_provider{encryption_algorithm_name};
            print_bcrypt_object_properties(offset + 2, encryption_provider, true);

            printf("%*cCreating key pair, key length %zu\n", offset, ' ', encryption_key_length);

            bcrypt::key k{encryption_provider.generate_empty_key_pair(encryption_key_length)};

            printf("%*cFinalizing key pair\n", offset, ' ');

            k.finalize_key_pair();

            print_bcrypt_object_properties(offset + 2, k, true);

            printf("\n%*cHashing data.\n", offset, ' ');

            h.hash_data(data_to_sign.data(), data_to_sign.size());
            hcrypt::buffer hash_value{h.finish()};

            printf("%*cHash length: %Iu\n", offset, ' ', hash_value.size());

            printf("%*chash: %ws\n", offset, ' ', hcrypt::to_hex(hash_value).c_str());

            printf("\n%*cSigning\n", offset, ' ');

            hcrypt::buffer signature{k.sign_hash(hash_value.data(), hash_value.size())};

            printf("%*cSignaure length: %Iu\n", offset, ' ', signature.size());

            printf("%*cSignature: %S\n", offset, ' ', hcrypt::to_hex(signature).c_str());

            printf("\n%*cExporting public key\n", offset, ' ');

            hcrypt::buffer public_key_blob{k.export_key(BCRYPT_DSA_PUBLIC_BLOB)};

            printf("%*cPublik key length: %Iu\n", offset, ' ', public_key_blob.size());

            printf("%*cPublic key: %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(public_key_blob).c_str());

            printf("\n%*cImporting public key\n", offset, ' ');

            bcrypt::key public_encryption_key{encryption_provider.import_key_pair(
                BCRYPT_DSA_PUBLIC_BLOB, public_key_blob.data(), public_key_blob.size())};
            print_bcrypt_object_properties(offset + 2, k, true);

            printf("\n%*cVerifying signatire using imported key\n", offset, ' ');

            if (public_encryption_key.verify_signature(nullptr,
                                                       hash_value.data(),
                                                       hash_value.size(),
                                                       signature.data(),
                                                       signature.size())) {
                printf("\n%*cSignature matches\n", offset, ' ');
            } else {
                printf("\n%*c!!! Signature does not matches !!!\n", offset, ' ');
            }

        } catch (std::system_error const &ex) {
            printf("%*ctest_message_signing, error code = 0x%x, %s\n",
                   offset,
                   ' ',
                   ex.code().value(),
                   ex.what());
        }
    }
} // namespace

void test_message_signing() {
    try {
        int offset{0};

        printf("\n---Test message signing---------------\n");

        printf("%*cGenerating random data.\n", offset + 2, ' ');

        hcrypt::buffer data_to_sign;
        data_to_sign.resize(150);
        bcrypt::generate_random(data_to_sign.data(), data_to_sign.size());

        printf("%*c%ws\n", offset + 2, ' ', hcrypt::to_hex(data_to_sign).c_str());

        std::for_each(std::begin(test_signing_algorithms),
                      std::end(test_signing_algorithms),
                      [offset, &data_to_sign](test_signing_algorithm_t const &algorithms) {
                          test_message_signing(offset + 2,
                                               algorithms.hashing_algorithm,
                                               algorithms.encryption_algorithm,
                                               algorithms.encription_key_length,
                                               data_to_sign);
                      });

    } catch (std::system_error const &ex) {
        printf("test_message_signing, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("\n----------------\n");
}
