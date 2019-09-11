#include "hcrypt_test_enum_algorithms.h"

namespace {
    void print_algorithms(int offset, ULONG ciypher_operations) {
        try {
            printf("%*c--Querying algorithms for cipher operations - %u, %ws\n",
                   offset,
                   ' ',
                   ciypher_operations,
                   bcrypt::algorithm_operations_to_string(ciypher_operations).c_str());

            bcrypt::find_first(bcrypt::enum_algorithms(ciypher_operations),
                            [offset](BCRYPT_ALGORITHM_IDENTIFIER const& algorithm_info) -> bool {
                                print(offset + 2, &algorithm_info);
                                return true;
                            });

        } catch (std::system_error const& ex) {
            printf("print_algorithms, error code = %u, %s\n",
                ex.code().value(),
                ex.what());
        }
    }
}

void print_algorithms() {
    try {
        int offset{ 0 };

        printf("---Enumirating algorithms---------------\n");

        ULONG ciypher_operations{ BCRYPT_CIPHER_OPERATION |
                                  BCRYPT_HASH_OPERATION |
                                  BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
                                  BCRYPT_SECRET_AGREEMENT_OPERATION |
                                  BCRYPT_SIGNATURE_OPERATION |
                                  BCRYPT_RNG_OPERATION };

        print_algorithms(offset + 2, ciypher_operations);
    } catch (std::system_error const& ex) {
        printf("resolve_providers, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}