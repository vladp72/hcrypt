#include "hbcrypt_test_key_derivation.hpp"
#include <algorithm>

namespace {

    BYTE generic_parameter[20] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    };

    BCryptBuffer SP800108ParamBuffer[] = {{
                                              sizeof(generic_parameter),
                                              KDF_GENERIC_PARAMETER,
                                              (PBYTE) generic_parameter,
                                          },
                                          {
                                              sizeof(BCRYPT_SHA256_ALGORITHM),
                                              KDF_HASH_ALGORITHM,
                                              (PBYTE) BCRYPT_SHA256_ALGORITHM,
                                          }};

    //
    // Sample Parameters for SP800-56A KDF
    //

    BYTE AlgorithmID[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    BYTE PartyUInfo[] = {0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33};

    BYTE PartyVInfo[] = {0x42, 0x4F, 0x42, 0x42, 0x59, 0x34, 0x35, 0x36};

    BCryptBuffer SP80056AParamBuffer[] = {{
                                              sizeof(AlgorithmID),
                                              KDF_ALGORITHMID,
                                              (PBYTE) AlgorithmID,
                                          },
                                          {
                                              sizeof(PartyUInfo),
                                              KDF_PARTYUINFO,
                                              (PBYTE) PartyUInfo,
                                          },
                                          {
                                              sizeof(PartyVInfo),
                                              KDF_PARTYVINFO,
                                              (PBYTE) PartyVInfo,
                                          },
                                          {
                                              sizeof(BCRYPT_SHA256_ALGORITHM),
                                              KDF_HASH_ALGORITHM,
                                              (PBYTE) BCRYPT_SHA256_ALGORITHM,
                                          }};

    //
    // Sample Parameters for PBKDF2
    //

    BYTE Salt[] = {
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
    };

    ULONGLONG IterationCount{12000};

    BCryptBuffer PBKDF2ParamBuffer[] = {{
                                            sizeof(Salt),
                                            KDF_SALT,
                                            (PBYTE) Salt,
                                        },
                                        {
                                            sizeof(IterationCount),
                                            KDF_ITERATION_COUNT,
                                            (PBYTE) &IterationCount,
                                        },
                                        {
                                            sizeof(BCRYPT_SHA256_ALGORITHM),
                                            KDF_HASH_ALGORITHM,
                                            (PBYTE) BCRYPT_SHA256_ALGORITHM,
                                        }};

    //
    // Sample Parameters for CAPI_KDF
    //

    BCryptBuffer CAPIParamBuffer[] = {{
        sizeof(BCRYPT_SHA256_ALGORITHM),
        KDF_HASH_ALGORITHM,
        (PBYTE) BCRYPT_SHA256_ALGORITHM,
    }};

    BCryptBufferDesc derivation_algorithms_parameters[] = {
        {NCRYPTBUFFER_VERSION, _countof(SP800108ParamBuffer), SP800108ParamBuffer},
        {NCRYPTBUFFER_VERSION, _countof(SP80056AParamBuffer), SP80056AParamBuffer},
        {NCRYPTBUFFER_VERSION, _countof(PBKDF2ParamBuffer), PBKDF2ParamBuffer},
        {NCRYPTBUFFER_VERSION, _countof(CAPIParamBuffer), CAPIParamBuffer},
    };

    LPCWSTR derivation_algorithms_to_test[] = {
        NCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        NCRYPT_SP80056A_CONCAT_ALGORITHM,
        NCRYPT_PBKDF2_ALGORITHM,
        NCRYPT_CAPI_KDF_ALGORITHM,
    };

    static_assert(_countof(derivation_algorithms_to_test) ==
                  _countof(derivation_algorithms_parameters));

    char const derivation_algorithms_secret[20] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    };

    wchar_t const persistent_key_name[] =
        L"ncrypt_library_test_key_derivation_F3686E9E-A097-4959-A014-"
        L"D8D2B2D9F42F";

    void test_sample_ncrypt_key_derivation(int offset,
                                           wchar_t const *algorithm,
                                           BCryptBufferDesc *description) {
        printf("\n%*cAlgorithm: %ws\n", offset, ' ', algorithm);

        offset += 2;

        try {
            ncrypt::storage_provider provider{MS_KEY_STORAGE_PROVIDER};

            print_ncrypt_object_properties(offset + 2, provider, true);

            printf("%*cCreating key %S for algorithm %S\n", offset, ' ', persistent_key_name, algorithm);

            ncrypt::key key{provider.create_key(
                algorithm, persistent_key_name, 0, NCRYPT_OVERWRITE_KEY_FLAG)};

            printf("%*cSetting secret value %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::begin(derivation_algorithms_secret),
                                  std::end(derivation_algorithms_secret))
                       .c_str());
            key.set_kdf_secret_value(derivation_algorithms_secret,
                                     sizeof(derivation_algorithms_secret));

            printf("%*cFinalizing key\n", offset, ' ');

            key.finalize_key();

            hcrypt::scope_guard delete_k{[&key, offset] {
                if (key) {
                    printf("%*cDeleting key %S\n", offset, ' ', persistent_key_name);
                    key.delete_key();
                    printf("%*cKey deleted\n", offset, ' ');
                }
            }};

            print_ncrypt_object_properties(offset + 2, key, true);

            printf("%*cDeriving key length 60 bytes\n", offset, ' ');

            hcrypt::buffer derived_key{key.key_derivation(60, description)};

            printf("%*cKey length: %Iu\n", offset + 2, ' ', derived_key.size());

            printf("%*cKey: %S\n", offset + 2, ' ', hcrypt::to_hex(derived_key).c_str());

        } catch (std::system_error const &ex) {
            printf(
                "%*ctest_sample_ncrypt_key_derivation, error code = 0x%x, %s\n",
                offset,
                ' ',
                ex.code().value(),
                ex.what());
        }
    }
} // namespace

void test_sample_ncrypt_key_derivation() {
    try {
        int offset{0};

        printf("\n---Test Sample Key Derivation---------------\n");

        for (size_t idx = 0; idx < _countof(derivation_algorithms_to_test); ++idx) {
            test_sample_ncrypt_key_derivation(offset + 2,
                                              derivation_algorithms_to_test[idx],
                                              &derivation_algorithms_parameters[idx]);
        }

    } catch (std::system_error const &ex) {
        printf("test_sample_ncrypt_key_derivation, error code = 0x%x, %s\n",
               ex.code().value(),
               ex.what());
    }
    printf("\n----------------\n");
}
