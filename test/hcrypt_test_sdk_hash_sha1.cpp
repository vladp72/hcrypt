#include "hcrypt_test_sdk_hash_sha1.h"

void test_sdk_sample_hash_sha1() {
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

        printf("%*cOpening algorithm SHA1.\n", 
               offset + 2, 
               ' ');

        bcrypt::algorithm_provider provider;
        provider.open(L"SHA1");
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
        printf("test_sdk_sample_hash_sha1, error code = 0x%x, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("\n----------------\n");
}
