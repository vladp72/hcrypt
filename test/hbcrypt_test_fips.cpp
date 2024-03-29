#include "hbcrypt_test_fips.hpp"

void print_is_fips_complience_on() {
    try {
        printf("---Query FIPS complience---------------\n");

        bool fips_complience_on{bcrypt::is_fips_complience_on()};

        printf("FIPS  complience on = %s\n", fips_complience_on ? "Yes" : "No");
    } catch (std::system_error const &ex) {
        printf("is_fips_complience_on, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("----------------\n");
}
