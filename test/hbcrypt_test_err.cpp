#include "hbcrypt_test_err.hpp"

void test_err() {
    std::error_code e1{hcrypt::status::invalid_signature};
    std::error_condition ec1{e1.default_error_condition()};
    std::error_code e2{NTE_BAD_SIGNATURE, std::system_category()};
    std::error_condition ec2{e2.default_error_condition()};

    BCRYPT_CODDING_ERROR_IF(e1 == e2);
    BCRYPT_CODDING_ERROR_IF(e2 == e1);

    BCRYPT_CODDING_ERROR_IF_NOT(ec1 == e2);
    BCRYPT_CODDING_ERROR_IF_NOT(e2 == ec1);

    BCRYPT_CODDING_ERROR_IF_NOT(ec2 == e1);
    BCRYPT_CODDING_ERROR_IF_NOT(e1 == ec2);

    BCRYPT_CODDING_ERROR_IF_NOT(ec2 == ec1);
    BCRYPT_CODDING_ERROR_IF_NOT(ec1 == ec2);
}
