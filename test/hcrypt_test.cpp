#include "hcrypt_test_helpers.h"
#include "hbcrypt_test_CTAD.h"
#include "hbcrypt_test_fips.h"
#include "hbcrypt_test_algorithms.h"
#include "hbcrypt_test_registered_providers.h"
#include "hbcrypt_test_enum_algorithms.h"
#include "hbcrypt_test_enum_contexts.h"
#include "hbcrypt_test_resolve_providers.h"
#include "hbcrypt_test_key_derivation.h"
#include "hbcrypt_test_hash.h"
#include "hbcrypt_test_message_signing.h"
#include "hbcrypt_test_rand.h"
#include "hbcrypt_test_dh_oakley.h"
#include "hbcrypt_test_sha1_hmac.h"
#include "hbcrypt_test_aes_cmac.h"
#include "hbcrypt_test_aes_cbc.h"
#include "hncrypt_test_providers.h"
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

        test_sha1_hmac();

        test_aes_cmac();

        test_aes_cbc();

        test_ncrypt_providers();

    } catch (std::system_error const& ex) {
        printf("Error code = 0x%x, %s, %s\n", 
               ex.code().value(), 
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
}

