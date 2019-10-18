#include "hbcrypt_test_enum_algorithms.hpp"

namespace {
    void print_algorithms(int offset, ULONG ciypher_operations) {
        try {
            printf(
                "%*c--Querying algorithms for cipher operations - %lu, %ws\n",
                offset,
                ' ',
                ciypher_operations,
                bcrypt::algorithm_operations_to_string(ciypher_operations).c_str());

            bcrypt::find_first(
                bcrypt::enum_algorithms(ciypher_operations),
                [offset](BCRYPT_ALGORITHM_IDENTIFIER const &algorithm_info) -> bool {
                    print(offset + 2, &algorithm_info);
                    return true;
                });

        } catch (std::system_error const &ex) {
            printf("print_algorithms, error code = 0x%x, %s\n", ex.code().value(), ex.what());
        }
    }
} // namespace

void print_algorithms() {
    try {
        int offset{0};

        printf("---Enumirating algorithms---------------\n");

        ULONG cypher_operations{BCRYPT_CIPHER_OPERATION | BCRYPT_HASH_OPERATION |
                                BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
                                BCRYPT_SECRET_AGREEMENT_OPERATION |
                                BCRYPT_SIGNATURE_OPERATION | BCRYPT_RNG_OPERATION};

        print_algorithms(offset + 2, cypher_operations);
    } catch (std::system_error const &ex) {
        printf("print_algorithms, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("----------------\n");
}