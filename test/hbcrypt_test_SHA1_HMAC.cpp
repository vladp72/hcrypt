#include "hbcrypt_test_SHA1_HMAC.hpp"
#include <algorithm>

namespace {

    unsigned char const message[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    unsigned char const hmac_key[] = {
        0x1b, 0x20, 0x5a, 0x9e, 0x2b, 0xe3, 0xfe, 0x85, 0x9c, 0x37,
        0xf1, 0xaf, 0xfe, 0x81, 0x88, 0x92, 0x63, 0x27, 0x38, 0x61,
    };

    wchar_t const *algorithms[] = {
        BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM,
        BCRYPT_SHA512_ALGORITHM,
    };

    void test_sha1_hmac(int offset, wchar_t const *algorithm) {
        try {
            printf("\n%*cCreating algorithm provider %S with "
                   "BCRYPT_ALG_HANDLE_HMAC_FLAG\n",
                   offset,
                   ' ',
                   algorithm);

            bcrypt::algorithm_provider ap{algorithm, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG};

            offset += 2;

            print_bcrypt_object_properties(offset + 2, ap, true);

            printf("%*cCreating reusable hash with key %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::cbegin(hmac_key), std::end(hmac_key)).c_str());

            bcrypt::hash h{ap.create_hash(reinterpret_cast<char const *>(hmac_key),
                                          sizeof(hmac_key),
                                          BCRYPT_HASH_REUSABLE_FLAG)};

            print_bcrypt_object_properties(offset + 2, h, true);

            for (int i = 0; i < 3; ++i) {
                h.hash_data(reinterpret_cast<char const *>(message), sizeof(message));
                hcrypt::buffer b{h.finish()};

                printf("%*c[%i] hash %S\n", offset, ' ', i, hcrypt::to_hex(b).c_str());
            }

        } catch (std::system_error const &ex) {
            printf("test_sha1_hmac, error code = 0x%x, %s, %s\n",
                   ex.code().value(),
                   hcrypt::status_to_string(ex.code().value()),
                   ex.what());
        }
        printf("----------------\n");
    }

} // namespace

void test_sha1_hmac() {
    try {
        int offset{0};

        printf("---SHA HMAC---------------\n");

        std::for_each(std::begin(algorithms), std::end(algorithms), [offset](wchar_t const *algorithm) {
            test_sha1_hmac(offset + 2, algorithm);
        });

    } catch (std::system_error const &ex) {
        printf("test_sha1_hmac, error code = 0x%x, %s, %s\n",
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("----------------\n");
}
