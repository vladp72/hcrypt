#include "hncrypt_test_strong_key_protection.hpp"
#include <algorithm>

namespace {

    unsigned char const msg[] = {
        0x04, 0x87, 0xec, 0x66, 0xa8, 0xbf, 0x17, 0xa6, 0xe3, 0x62, 0x6f, 0x1a,
        0x55, 0xe2, 0xaf, 0x5e, 0xbc, 0x54, 0xa4, 0xdc, 0x68, 0x19, 0x3e, 0x94,
    };

    wchar_t const pin[] = L"Password123";

    wchar_t const persistent_key_name[] =
        L"ncrypt_library_test_key_rsa_F3686E9E-A097-4959-A014-D8D2B2D9F42F";

    wchar_t const *hash_algorithms[] = {
        BCRYPT_SHA1_ALGORITHM,
    };

    wchar_t const *signing_algorithms[] = {
        NCRYPT_RSA_ALGORITHM,
    };

    void test_strong_key_protection(int offset,
                                    wchar_t const *hashing_algorithm,
                                    wchar_t const *signing_algorithm) {
        try {
            printf("\n%*cHashing algorithm %S, ECDSA algorithm %S\n", offset, ' ', hashing_algorithm, signing_algorithm);

            offset += 2;

            bcrypt::algorithm_provider hash_ap{hashing_algorithm};
            print_bcrypt_object_properties(offset + 2, hash_ap, true);

            printf("%*cCreating hash\n", offset, ' ');
            bcrypt::hash h{hash_ap.create_hash()};
            print_bcrypt_object_properties(offset + 2, h, true);

            unsigned long hash_size{h.get_hash_length()};

            printf("%*cHashing message %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::cbegin(msg), std::end(msg)).c_str());

            h.hash_data(reinterpret_cast<char const *>(msg), sizeof(msg));
            hcrypt::buffer data_hash{h.finish()};

            printf(
                "%*cMessage Hash %S\n", offset, ' ', hcrypt::to_hex(data_hash).c_str());

            printf("%*cOpening storage provider %S\n", offset, ' ', MS_KEY_STORAGE_PROVIDER);
            ncrypt::storage_provider sp{MS_KEY_STORAGE_PROVIDER};
            print_ncrypt_object_properties(offset + 2, sp, true);

            if (sp.delete_key(persistent_key_name)) {
                printf("%*cFound and deleted key %S\n", offset, ' ', persistent_key_name);
            }

            printf("%*cCreating key algorithm %S, name %S\n", offset, ' ', signing_algorithm, persistent_key_name);

            ncrypt::key k{sp.create_key(
                signing_algorithm, persistent_key_name, AT_SIGNATURE, NCRYPT_OVERWRITE_KEY_FLAG)};

            printf("%*cSetting UI policy\n", offset, ' ');

            NCRYPT_UI_POLICY ui_policy{};
            ui_policy.dwVersion = 1;
            ui_policy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;

            ui_policy.pszCreationTitle = L"Strong Key UX Sample";
            ui_policy.pszFriendlyName = L"Sample Friendly Name";
            ui_policy.pszDescription = L"This is a sample strong key";

            k.set_ui_policy(&ui_policy, sizeof(ui_policy));

            printf("%*cSetting window handle\n", offset, ' ');

            HWND hwnd_console = GetDesktopWindow();
            if (NULL == hwnd_console) {
                throw std::system_error(hcrypt::win32_error(GetLastError()),
                                        "GetDesktopWindow failed");
            }

            k.set_hwnd(hwnd_console);

            printf("%*cEnter PIN %S\n", offset, ' ', pin);

            k.finalize_key();

            hcrypt::scope_guard delete_k{[&sp, offset] {
                if (sp) {
                    printf("%*cDeleting key %S\n", offset, ' ', persistent_key_name);
                    sp.delete_key(persistent_key_name);
                    printf("%*cKey deleted\n", offset, ' ');
                }
            }};

            printf("%*cClosing key\n", offset, ' ');
            k.close();

            printf("%*cReopening key\n", offset, ' ');
            k = sp.open_key(persistent_key_name, AT_SIGNATURE);

            printf("%*cSetting pin %S\n", offset, ' ', pin);
            k.set_pin_property(pin);

            print_ncrypt_object_properties(offset + 2, k, true);

            printf("%*cSigning Hash\n", offset, ' ');

            BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo{};
            PKCS1PaddingInfo.pszAlgId = hashing_algorithm;

            hcrypt::buffer hash_signature{k.sign_hash(
                data_hash.data(), data_hash.size(), &PKCS1PaddingInfo, NCRYPT_PAD_PKCS1_FLAG)};
            printf(
                "%*cSignature %S\n", offset, ' ', hcrypt::to_hex(hash_signature).c_str());

            printf("%*cExporting public key\n", offset, ' ');
            hcrypt::buffer exported_public_key{k.export_key(BCRYPT_RSAPUBLIC_BLOB)};
            printf("%*cPublic key %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(exported_public_key).c_str());

            printf("%*cCreating signing algorithm provider %S\n", offset, ' ', signing_algorithm);
            bcrypt::algorithm_provider signing_ap{signing_algorithm};
            print_bcrypt_object_properties(offset + 2, signing_ap, true);

            printf("%*cImporting public key\n", offset, ' ');
            bcrypt::key public_key{
                signing_ap.import_key_pair(BCRYPT_RSAPUBLIC_BLOB,
                                           exported_public_key.data(),
                                           exported_public_key.size())};
            print_bcrypt_object_properties(offset + 2, public_key, true);

            printf("%*cVerifying signature\n", offset, ' ');
            BCRYPT_CODDING_ERROR_IF_NOT(
                public_key.verify_signature(&PKCS1PaddingInfo,
                                            data_hash.data(),
                                            data_hash.size(),
                                            hash_signature.data(),
                                            hash_signature.size(),
                                            BCRYPT_PAD_PKCS1));

            printf("%*cVerification succeeded\n", offset, ' ');
            //
            // Mess with hash
            //
            hcrypt::buffer broken_data_hash{data_hash};
            broken_data_hash[1] += 1;

            printf("%*cVerifying signature for broken hash %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(broken_data_hash).c_str());

            BCRYPT_CODDING_ERROR_IF(
                public_key.verify_signature(&PKCS1PaddingInfo,
                                            broken_data_hash.data(),
                                            broken_data_hash.size(),
                                            hash_signature.data(),
                                            hash_signature.size(),
                                            BCRYPT_PAD_PKCS1));

            printf("%*cVerification failed as expected\n", offset, ' ');

            //
            // Mess with signature
            //

            hcrypt::buffer broken_hash_signature{hash_signature};
            broken_hash_signature[1] += 1;

            printf("%*cVerifying signature for broken signature %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(broken_hash_signature).c_str());

            BCRYPT_CODDING_ERROR_IF(
                public_key.verify_signature(&PKCS1PaddingInfo,
                                            data_hash.data(),
                                            data_hash.size(),
                                            broken_hash_signature.data(),
                                            broken_hash_signature.size(),
                                            BCRYPT_PAD_PKCS1));

            printf("%*cVerification failed as expected\n", offset, ' ');

        } catch (std::system_error const &ex) {
            printf("%*ctest_ecdsa, error code = 0x%x, %s\n",
                   offset,
                   ' ',
                   ex.code().value(),
                   ex.what());
        }
        printf("----------------\n");
    }

} // namespace

void test_strong_key_protection() {
    try {
        int offset{0};

        printf("---Strong Key Protection-------\n");

        std::for_each(std::begin(hash_algorithms),
                      std::end(hash_algorithms),
                      [offset](wchar_t const *hash_algorithm) {
                          std::for_each(
                              std::begin(signing_algorithms),
                              std::end(signing_algorithms),
                              [offset, hash_algorithm](wchar_t const *signing_algorithm) {
                                  test_strong_key_protection(
                                      offset + 2, hash_algorithm, signing_algorithm);
                              });
                      });
    } catch (std::system_error const &ex) {
        printf("test_ecdsa, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("----------------\n");
}
