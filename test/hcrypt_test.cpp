#include "hcrypt_test_helpers.h"
#include "hcrypt_test_CTAD.h"
#include "hcrypt_test_fips.h"
#include "hcrypt_test_algorithms.h"
#include "hcrypt_test_registered_providers.h"
#include "hcrypt_test_enum_algorithms.h"
#include "hcrypt_test_enum_contexts.h"
#include "hcrypt_test_resolve_providers.h"
#include "hcrypt_test_key_derivation.h"
#include "hcrypt_test_hash.h"
#include "hcrypt_test_message_signing.h"
#include "hcrypt_test_rand.h"
#include "hcrypt_test_dh_oakley.h"
//
// https://github.com/microsoft/Windows-classic-samples/tree/master/Samples/Security
//

int main() {

    try {
        test_CTAD();

        print_is_fips_complience_on();

        print_registered_providers();

        resolve_providers();

        print_algorithms();

        print_crypto_contexts();

        test_algorithm();

        test_rand();

        test_sample_key_derivation();

        test_sample_hash();

        test_message_signing();

        tesh_dh_oakley();

    } catch (std::system_error const& ex) {
        printf("Error code = %u, %s\n", ex.code().value(), ex.what());
    }
}

