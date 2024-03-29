#include "hcrypt_test_helpers.hpp"
#include "hbcrypt_test_CTAD.hpp"
#include "hbcrypt_test_err.hpp"
#include "hbcrypt_test_base64.hpp"
#include "hbcrypt_test_fips.hpp"
#include "hbcrypt_test_algorithms.hpp"
#include "hbcrypt_test_registered_providers.hpp"
#include "hbcrypt_test_enum_algorithms.hpp"
#include "hbcrypt_test_enum_contexts.hpp"
#include "hbcrypt_test_resolve_providers.hpp"
#include "hbcrypt_test_key_derivation.hpp"
#include "hbcrypt_test_hash.hpp"
#include "hbcrypt_test_message_signing.hpp"
#include "hbcrypt_test_rand.hpp"
#include "hbcrypt_test_dh_oakley.hpp"
#include "hbcrypt_test_SHA1_HMAC.hpp"
#include "hbcrypt_test_AES_CMAC.hpp"
#include "hbcrypt_test_AES_CBC.hpp"
#include "hncrypt_test_providers.hpp"
#include "hncrypt_test_enum_keys.hpp"
#include "hncrypt_test_ECDSA256.hpp"
#include "hncrypt_test_strong_key_protection.hpp"
#include "hncrypt_test_key_derivation.hpp"
#include "credman_tests.hpp"

#include "perf\numa.hpp"

#include "hbcrypt_perf_hash.hpp"
#include "hbcrypt_perf_base64.hpp"

int main() {
    try {

        //
        // credential manager tests
        //
        test_enumirate_supported_persistence_types();

        test_enumirate_all_credentials();

        test_get_target_info();

        test_protect_unprotect();

        test_creds_lifetime();

        test_pack_unpack_auth_buffer();

        //
        // CNG tests
        //

        test_CTAD();

        test_err();

        test_base64();

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

        test_ncrypt_enum_keys();

        test_ecdsa();

        test_sample_ncrypt_key_derivation();

        //
        // Uncomment to run perf tests
        //


        //perf_compare_hash();

        //perf_hash_compare_buffer_sizes(BCRYPT_MD5_ALGORITHM);

        //perf_hash_compare_buffer_sizes(BCRYPT_SHA1_ALGORITHM);

        //perf_hash_compare_buffer_sizes(BCRYPT_SHA256_ALGORITHM);

        //perf_base64_compare_buffer_sizes();


        //
        // This test prompts user to enter password that
        // protects key. Run it only in interactive mode
        //
        // test_strong_key_protection();

        //
        // uncomment if you need to explore output of library on your computer
        //
        // numa::test_all();

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}
