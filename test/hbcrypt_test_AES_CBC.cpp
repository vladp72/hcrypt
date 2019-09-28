#include "hbcrypt_test_aes_cbc.hpp"
#include <algorithm>

namespace {

    unsigned char const plain_text[] = "Text1 to encrypt";

    unsigned char const iv[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    unsigned char const key128[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    wchar_t const *algorithms[] = {
        BCRYPT_AES_ALGORITHM,
    };

    wchar_t const *chaining_modes[] = {
        BCRYPT_CHAIN_MODE_CBC,
        BCRYPT_CHAIN_MODE_ECB,
        BCRYPT_CHAIN_MODE_CFB,
    };

    void test_aes_cbc(int offset, wchar_t const *algorithm, wchar_t const *chain_mode) {
        try {
            printf("\n%*cCreating algorithm provider %S, chaining mode %S\n", offset, ' ', algorithm, chain_mode);

            bcrypt::algorithm_provider ap{algorithm};

            offset += 2;

            print_object_properties(offset + 2, ap, true);

            printf("%*cSetting chaining mode to %S\n", offset, ' ', chain_mode);

            ap.set_chaining_mode(chain_mode);
            print_object_properties(offset + 2, ap, true);

            size_t block_length{ap.get_block_length()};

            //
            // In ECB mode algorithm does not take IV
            //
            // ECB - electronic codebook
            //
            // A block cipher mode(each block is encrypted individually) that uses no feedback.
            // This means any blocks of plaintext that are identical(either in the same message
            // or in a different message that is encrypted with the same key) is transformed
            // into identical ciphertext blocks.Initialization vectors cannot be used with this
            // cipher mode.If a single bit of the ciphertext block is garbled, then the entire
            // corresponding plaintext block is also garbled.
            //
            bool const is_ecb_mode{std::wstring_view(BCRYPT_CHAIN_MODE_ECB) == chain_mode};

            if (sizeof(iv) < block_length) {
                printf("!!! %*cInitialization Vector must bre longer than "
                       "block length !!!\n",
                       offset,
                       ' ');
                throw std::system_error(hcrypt::status::buffer_too_small, "IV is too small");
            }

            hcrypt::buffer iv_buffer{std::begin(iv), std::begin(iv) + block_length};

            printf("%*cIV: %S\n", offset, ' ', hcrypt::to_hex(iv_buffer).c_str());

            printf("%*cCreating symmetric key using %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::begin(key128), std::end(key128)).c_str());

            bcrypt::key k_a{ap.generate_symmetric_key(
                reinterpret_cast<char const *>(key128), 16)};

            print_object_properties(offset + 2, k_a, true);

            printf("%*cExporting key\n", offset, ' ');

            hcrypt::buffer exported_key{k_a.export_key(BCRYPT_OPAQUE_KEY_BLOB)};

            printf("%*cKey: %S\n", offset, ' ', hcrypt::to_hex(exported_key).c_str());

            size_t data_size{sizeof(plain_text)};
            size_t block_size{ap.get_block_length()};
            size_t padded_size{hcrypt::round_to_block(data_size, block_size)};
            hcrypt::buffer data_buffer(padded_size);
            std::copy(std::begin(plain_text), std::end(plain_text), std::begin(data_buffer));

            printf("%*cEncrypting data: size %zu, padded %zu, \"%s\",\"%S\"\n",
                   offset,
                   ' ',
                   data_size,
                   padded_size,
                   std::string_view(data_buffer.data(), data_size).data(),
                   hcrypt::to_hex(data_buffer).c_str());

            size_t bytes_encrypted{0};

            //
            // AES is a block algorithm, and BCRYPT_BLOCK_PADDING
            // tells it that this is last block that might not be
            // block alligned, and have to be padded
            //

            k_a.encrypt(data_buffer.data(),
                        data_size,
                        nullptr,
                        is_ecb_mode ? nullptr : iv_buffer.data(),
                        is_ecb_mode ? 0 : iv_buffer.size(),
                        data_buffer.data(),
                        data_buffer.size(),
                        &bytes_encrypted,
                        BCRYPT_BLOCK_PADDING);

            printf("%*cEncrypted data: %zu, \"%S\"\n",
                   offset,
                   ' ',
                   bytes_encrypted,
                   hcrypt::to_hex(data_buffer).c_str());

            printf("%*cImporting key\n", offset, ' ');

            bcrypt::key k_b{ap.import_symetric_key(nullptr,
                                                   BCRYPT_OPAQUE_KEY_BLOB,
                                                   exported_key.data(),
                                                   exported_key.size())};

            print_object_properties(offset + 2, k_b, true);

            iv_buffer.assign(std::begin(iv), std::begin(iv) + block_length);

            printf("%*cDecrypting data, IV: %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(iv_buffer).c_str());

            size_t bytes_decrypted{0};

            if (k_b.decrypt(data_buffer.data(),
                            data_buffer.size(),
                            nullptr,
                            is_ecb_mode ? nullptr : iv_buffer.data(),
                            is_ecb_mode ? 0 : iv_buffer.size(),
                            data_buffer.data(),
                            data_buffer.size(),
                            &bytes_decrypted,
                            BCRYPT_BLOCK_PADDING)) {
                printf("%*cDecrypted data: %zu, \"%s\",\"%S\"\n",
                       offset,
                       ' ',
                       bytes_decrypted,
                       std::string(data_buffer.data(), data_size).c_str(),
                       hcrypt::to_hex(data_buffer).c_str());

            } else {
                printf("!!! %*cMessage authentication failed !!!\n", offset, ' ');
                throw std::system_error(hcrypt::status::auth_tag_mismatch, "IV is too small");
            }

        } catch (std::system_error const &ex) {
            printf("test_aes_cbc, error code = 0x%x, %s, %s\n",
                   ex.code().value(),
                   hcrypt::status_to_string(ex.code().value()),
                   ex.what());
        }
        printf("----------------\n");
    }

} // namespace

void test_aes_cbc() {
    try {
        int offset{0};

        printf("---AES CBC---------------\n");

        std::for_each(std::begin(algorithms), std::end(algorithms), [offset](wchar_t const *algorithm) {
            std::for_each(std::begin(chaining_modes),
                          std::end(chaining_modes),
                          [offset, algorithm](wchar_t const *chaining_mode) {
                              test_aes_cbc(offset + 2, algorithm, chaining_mode);
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
