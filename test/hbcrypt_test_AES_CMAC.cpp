#include "hbcrypt_test_AES_CMAC.hpp"
#include <algorithm>

namespace {

    //unsigned char const message[] = {
    //    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03,
    //    0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    //    0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    //};

    unsigned char const key[] = {
        0x1b, 0x20, 0x5a, 0x9e, 0x2b, 0xe3, 0xfe, 0x85, 0x9c, 0x37, 0xf1,
        0xaf, 0xfe, 0x81, 0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81,
        0x88, 0x92, 0x9c, 0x37, 0xf1, 0xaf, 0xfe, 0x81, 0x88, 0x92,
    };

    wchar_t const *algorithms[] = {
        BCRYPT_AES_ALGORITHM,
    };

    wchar_t const *chaining_modes[] = {
        BCRYPT_CHAIN_MODE_CCM,
        BCRYPT_CHAIN_MODE_GCM,
    };

    void test_aes_cmac(int offset, wchar_t const *algorithm, wchar_t const *chain_mode) {
        try {
            printf("\n%*cCreating algorithm provider %S, chaining mode %S\n", offset, ' ', algorithm, chain_mode);

            bcrypt::algorithm_provider ap{algorithm};

            offset += 2;

            print_bcrypt_object_properties(offset + 2, ap, true);

            printf("%*cSetting chaining mode to %S\n", offset, ' ', chain_mode);

            ap.set_chaining_mode(chain_mode);
            print_bcrypt_object_properties(offset + 2, ap, true);

            printf("%*cCreating symmetric key\n", offset, ' ');

            bcrypt::key k{ap.generate_symmetric_key(
                reinterpret_cast<char const *>(key), 32)};

            print_bcrypt_object_properties(offset + 2, k, true);

            // The data to be GMAC'd. It is not encrypted.
            std::string_view aad(
                "Not so secret additionally authenticated data");

            for (int idx{0}; idx < 3; ++idx) {
                UCHAR iv[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc};

                UCHAR tag[16] = {0};

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aadInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(aadInfo);

                aadInfo.pbNonce = iv;
                aadInfo.cbNonce = sizeof(iv);

                // Awful API design; non-const pointer.
                aadInfo.pbAuthData =
                    reinterpret_cast<UCHAR *>(const_cast<char *>(&aad[0]));
                aadInfo.cbAuthData = static_cast<ULONG>(aad.size());
                aadInfo.cbAAD = static_cast<ULONG>(aad.size());

                aadInfo.pbTag = tag;
                aadInfo.cbTag = sizeof(tag);

                size_t bytes_written{0};

                printf("%*cEncrypting\n", offset, ' ');

                k.encrypt(nullptr, 0, &aadInfo, nullptr, 0, nullptr, 0, &bytes_written);

                printf("%*cHash %S\n",
                       offset,
                       ' ',
                       hcrypt::to_hex(std::begin(tag), std::end(tag)).c_str());
            }

        } catch (std::system_error const &ex) {
            printf("test_aes_cmac, error code = 0x%x, %s, %s\n",
                   ex.code().value(),
                   hcrypt::status_to_string(ex.code().value()),
                   ex.what());
        }
        printf("----------------\n");
    }

} // namespace

void test_aes_cmac() {
    try {
        int offset{0};

        printf("---AES CMAC---------------\n");

        std::for_each(std::begin(algorithms), std::end(algorithms), [offset](wchar_t const *algorithm) {
            std::for_each(std::begin(chaining_modes),
                          std::end(chaining_modes),
                          [offset, algorithm](wchar_t const *chaining_mode) {
                              test_aes_cmac(offset + 2, algorithm, chaining_mode);
                          });
        });

    } catch (std::system_error const &ex) {
        printf("test_aes_cmac, error code = 0x%x, %s, %s\n",
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("----------------\n");
}
