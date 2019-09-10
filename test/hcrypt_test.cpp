#include "hcrypt_test_helpers.h"
#include "hcrypt_test_CTAD.h"
#include "hcrypt_test_fips.h"
#include "hcrypt_test_algorithms.h"
#include "hcrypt_test_registered_providers.h"
#include "hcrypt_test_enum_algorithms.h"
#include "hcrypt_test_enum_contexts.h"
#include "hcrypt_test_resolve_providers.h"
#include "hcrypt_test_sdk_key_derivation.h"
#include "hcrypt_test_sdk_hash.h"

int main() {

    try {
        test_CTAD();

        print_is_fips_complience_on();

        print_registered_providers();

        resolve_providers();

        print_algorithms();

        print_crypto_contexts();

        test_algorithm();

        test_sdk_sample_key_derivation();

        test_sdk_sample_hash();

    } catch (std::system_error const& ex) {
        printf("Error code = %u, %s\n", ex.code().value(), ex.what());
    }
}

