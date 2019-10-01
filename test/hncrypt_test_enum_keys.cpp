#include "hncrypt_test_enum_keys.hpp"

void enum_keys(int offset, NCryptProviderName const &provider_name, unsigned long flags) {
    printf("\n%*cProvider \"%S\", comment \"%S\" with flags 0x%lx, %S :\n",
           offset,
           ' ',
           provider_name.pszName,
           provider_name.pszComment,
           flags,
           ncrypt::enum_flags_to_string(flags).c_str());
    try {
        ncrypt::storage_provider sp{provider_name.pszName};

        print_ncrypt_object_properties(offset + 2, sp, true);

        ncrypt::storage_provider::key_iterator cur{sp.key_begin(flags)};
        ncrypt::storage_provider::key_iterator end{};

        for (; cur != end; ++cur) {
            NCryptKeyName const &key_name{*cur};
            print(offset + 4, key_name);

            ncrypt::key k;

            std::error_code key_status{sp.try_open_key(
                key_name.pszName, key_name.dwLegacyKeySpec, key_name.dwFlags, &k)};

            if (hcrypt::is_success(key_status)) {
                print_ncrypt_object_properties(offset + 6, k, true);
            } else {
                printf("%*copen_keys, error code = 0x%x, %s\n",
                       offset + 2,
                       ' ',
                       key_status.value(),
                       hcrypt::status_to_string(key_status.value()));
            }
        }

    } catch (std::system_error const &ex) {
        printf("%*cenum_keys, error code = 0x%x, %s, %s\n",
               offset + 2,
               ' ',
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
}

void test_ncrypt_enum_keys() {
    int offset{0};

    printf("\n---Testing hncrypt::enum_keys---------------\n");

    try {
        for_each(ncrypt::enum_providers(), [offset](NCryptProviderName const &name) {
            enum_keys(offset, name, NCRYPT_SILENT_FLAG);
            enum_keys(offset, name, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        });

    } catch (std::system_error const &ex) {
        printf("%*ctest_ncrypt_providers, error code = 0x%x, %s, %s\n",
               offset,
               ' ',
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("\n----------------\n");
}
