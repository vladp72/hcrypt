#include "hcrypt_test_sdk_hash.h"
#include <algorithm>

namespace {

    wchar_t const* hash_algorithms[]{
        BCRYPT_MD2_ALGORITHM,
        BCRYPT_MD4_ALGORITHM,
        BCRYPT_MD5_ALGORITHM,
        BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM,
        BCRYPT_SHA512_ALGORITHM
    };

    void test_sdk_sample_hash(int offset, 
                              wchar_t const* algorithm_name,
                              hcrypt::buffer const &data_to_hash) {
        try {
            printf("\n%*cOpening algorithm %S.\n", 
                   offset + 2, 
                   ' ',
                   algorithm_name);

            bcrypt::algorithm_provider provider{ algorithm_name };
            print_object_properties(offset + 4, provider, true);

            printf("%*cCreating hash object.\n", 
                   offset + 2, 
                   ' ');

            bcrypt::hash h{ provider.create_hash() };
            print_object_properties(offset + 4, h, true);

            printf("%*cHashing data.\n",
                offset + 2,
                ' ');

            h.hash_data(data_to_hash.data(),
                        data_to_hash.size());
            hcrypt::buffer hash_value{ h.finish() };

            printf("%*cHash length: %Iu\n", 
                   offset + 2, 
                   ' ', 
                   hash_value.size());

            printf("%*chas: %ws\n", 
                   offset + 2, 
                   ' ', 
                   hcrypt::to_hex(hash_value).c_str());

        } catch (std::system_error const& ex) {
            printf("test_sdk_sample_hash, error code = 0x%x, %s\n",
                ex.code().value(),
                ex.what());
        }
    }
} // namespace

void test_sdk_sample_hash() {
    try {
        int offset{ 0 };

        printf("\n---Test Sample Hash SHA1---------------\n");

        printf("%*cGenerating random data.\n", 
               offset + 2, 
               ' ');

        hcrypt::buffer data_to_hash;
        data_to_hash.resize(150);
        bcrypt::generate_random(data_to_hash.data(), 
                                data_to_hash.size());
        
        printf("%*c%ws\n", 
               offset + 2, 
               ' ', 
               hcrypt::to_hex(data_to_hash).c_str());

        std::for_each(std::begin(hash_algorithms), 
                      std::end(hash_algorithms),
                      [offset, &data_to_hash](wchar_t const* algorithm_name) {
                          test_sdk_sample_hash(offset + 2,
                                               algorithm_name,
                                               data_to_hash);
                      });

    } catch (std::system_error const& ex) {
        printf("test_sdk_sample_hash, error code = 0x%x, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("\n----------------\n");
}
