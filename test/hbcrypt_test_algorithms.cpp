#include "hbcrypt_test_algorithms.h"

void test_algorithm() {
    printf("---Testing bcrypt::algorithm_provider---------------\n");
    try {

        int offset{ 0 };

        bcrypt::algorithm_provider ap;

        ap.open(BCRYPT_AES_ALGORITHM);

        print_object_properties(offset + 2, ap);


    } catch (std::system_error const& ex) {
        printf("test_algorithm, error code = ox%x, %s, %s\n",
            ex.code().value(),
            hcrypt::status_to_string(ex.code().value()),
            ex.what());
    }
    printf("----------------\n");
}
