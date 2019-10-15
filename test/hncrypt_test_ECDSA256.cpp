#include "hncrypt_test_ECDSA256.hpp"
#include <algorithm>

namespace {

    unsigned char const msg[] = {
        0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6, 0xe3, 0x62, 0x6f, 0x1a,
        0x55, 0xe2, 0xaf, 0x5e, 0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
    };

    wchar_t const persistent_key_name[] =
        L"ncrypt_library_test_key_ecdsa_F3686E9E-A097-4959-A014-D8D2B2D9F42F";

    wchar_t const *algorithms[] = {
        BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM,
        BCRYPT_SHA512_ALGORITHM,
    };

    void test_ecdsa(int offset, wchar_t const *hashing_algorithm) {
        try {
            printf("\n%*cCreating hashing algorithm provider %S\n", offset, ' ', hashing_algorithm);
            bcrypt::algorithm_provider hash_ap{hashing_algorithm};
            print_bcrypt_object_properties(offset + 2, hash_ap, true);

            // offset += 2;

            printf("%*cCreating hash\n", offset, ' ');
            bcrypt::hash h{hash_ap.create_hash()};
            print_bcrypt_object_properties(offset + 2, h, true);

            unsigned long hash_size{h.get_hash_length()};

            printf("%*cHashing message %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::cbegin(msg), std::end(msg)).c_str());

            h.hash_data(reinterpret_cast<char const *>(msg), sizeof(msg));
            hcrypt::buffer data_hash{h.finish()};

            printf(
                "%*cMessage Hash %S\n", offset, ' ', hcrypt::to_hex(data_hash).c_str());

            printf("%*cOpening storage provider %S\n", offset, ' ', MS_KEY_STORAGE_PROVIDER);
            ncrypt::storage_provider sp{MS_KEY_STORAGE_PROVIDER};
            print_ncrypt_object_properties(offset + 2, sp, true);

            printf("%*cCreating or openning key algorithm %S, name %S\n",
                   offset,
                   ' ',
                   NCRYPT_ECDSA_P256_ALGORITHM,
                   persistent_key_name);
            
            ncrypt::key k;

            std::error_code error{sp.try_open_key(persistent_key_name, 0, 0, &k)};
            if (error != hcrypt::win32_error(ERROR_SUCCESS)) {
                printf("%*cOpen failed with errorerror code = 0x%x, %s. Trying "
                       "to create.\n",
                       offset,
                       ' ',
                       error.value(),
                       error.message().c_str());
                k = sp.create_key(NCRYPT_ECDSA_P256_ALGORITHM, persistent_key_name);
                k.finalize_key();
            } else {
                printf("%*cOpened existing key\n", offset, ' ');
            }

            print_ncrypt_object_properties(offset + 2, k, true);

            printf("%*cSigning Hash\n", offset, ' ');
            hcrypt::buffer hash_signature{
                k.sign_hash(data_hash.data(), data_hash.size())};
            printf(
                "%*cSignature %S\n", offset, ' ', hcrypt::to_hex(hash_signature).c_str());

            printf("%*cExporting public key\n", offset, ' ');
            hcrypt::buffer exported_public_key{k.export_key(BCRYPT_ECCPUBLIC_BLOB)};
            printf("%*cPublic key %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(exported_public_key).c_str());

            printf("%*cCreating signing algorithm provider %S\n", offset, ' ', BCRYPT_ECDSA_P256_ALGORITHM);
            bcrypt::algorithm_provider signing_ap{BCRYPT_ECDSA_P256_ALGORITHM};
            print_bcrypt_object_properties(offset + 2, signing_ap, true);

            printf("%*cImporting public key\n", offset, ' ');
            bcrypt::key public_key{
                signing_ap.import_key_pair(BCRYPT_ECCPUBLIC_BLOB,
                                           exported_public_key.data(),
                                           exported_public_key.size())};
            print_bcrypt_object_properties(offset + 2, public_key, true);

            printf("%*cVerifying signature\n", offset, ' ');
            if (public_key.verify_signature(nullptr,
                                            data_hash.data(),
                                            data_hash.size(),
                                            hash_signature.data(),
                                            hash_signature.size())) {
                printf("%*cVerification succeeded\n", offset, ' ');
            } else {
                printf("%*cVerification failed\n", offset, ' ');
            }

            k.delete_key();

        } catch (std::system_error const &ex) {
            printf("%*ctest_ecdsa, error code = 0x%x, %s, %s\n",
                   offset,
                   ' ',
                   ex.code().value(),
                   hcrypt::status_to_string(ex.code().value()),
                   ex.what());
        }
        printf("----------------\n");
    }

} // namespace

void test_ecdsa() {
    try {
        int offset{0};

        printf("---ECDSA---------------\n");

        std::for_each(std::begin(algorithms), std::end(algorithms), [offset](wchar_t const *algorithm) {
            test_ecdsa(offset + 2, algorithm);
        });

    } catch (std::system_error const &ex) {
        printf("test_ecdsa, error code = 0x%x, %s, %s\n",
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("----------------\n");
}
