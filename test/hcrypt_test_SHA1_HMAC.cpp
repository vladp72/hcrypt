#include "hcrypt_test_sha1_hmac.h"

namespace {

    unsigned char const message[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    unsigned char const hmac_key[] = {
        0x1b, 0x20, 0x5a, 0x9e, 0x2b, 0xe3, 0xfe, 0x85,
        0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81, 0x88, 0x92,
        0x63, 0x27, 0x38, 0x61,
    };

} //namespace

void test_sha1_hmac() {
    try {
        int offset{ 0 };

        printf("---SHA1 HMAC---------------\n");

        
        printf("\n%*cCreating algorithm provider with BCRYPT_ALG_HANDLE_HMAC_FLAG, %S\n",
                offset,
                ' ',
                 BCRYPT_SHA1_ALGORITHM);

        bcrypt::algorithm_provider ap{ BCRYPT_SHA1_ALGORITHM,
                                       nullptr,
                                       BCRYPT_ALG_HANDLE_HMAC_FLAG };

        offset += 2;

        print_object_properties(offset + 2, ap, true);

        printf("\n%*cCreating reusable hash with key %S\n",
                offset,
                ' ',
                hcrypt::to_hex(std::cbegin(hmac_key), std::end(hmac_key)).c_str());

        bcrypt::hash h{ ap.create_hash(reinterpret_cast<char const *>(hmac_key),
                                       sizeof(hmac_key),
                                       BCRYPT_HASH_REUSABLE_FLAG) };

        print_object_properties(offset + 2, h, true);

        for (int i = 0; i < 10; ++i) {
            h.hash_data(reinterpret_cast<char const*>(message), 
                        sizeof(message));
            hcrypt::buffer b{ h.finish()};

            printf("\n%*c[%i] hash %S\n",
                    offset,
                    ' ',
                    i,
                    hcrypt::to_hex(b).c_str());
        }

    } catch (std::system_error const& ex) {
        printf("test_sha1_hmac, error code = 0x%x, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}
