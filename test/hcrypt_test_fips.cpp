#include "hcrypt_test_fips.h"

void print_is_fips_complience_on() {
    try {
        int offset{ 0 };

        printf("---Query FIPS complience---------------\n");

        bool fips_complience_on{ bcrypt::is_fips_complience_on() };

        printf("FIPS  complience on = %s\n", 
               fips_complience_on ? "Yes" : "No");
    } catch (std::system_error const& ex) {
        printf("is_fips_complience_on, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}
