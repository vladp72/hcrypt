#include "hncrypt_test_providers.hpp"

void test_ncrypt_providers() {
    int offset{0};

    printf("\n---Testing hncrypt::enum_providers---------------\n");

    try {
        find_first(ncrypt::enum_providers(), [offset](NCryptProviderName const &name) -> bool {
            printf("%*cProvider \"%S\", comment \"%S\"\n", offset, ' ', name.pszName, name.pszComment);
            return true;
        });

    } catch (std::system_error const &ex) {
        printf("%*ctest_ncrypt_providers, error code = ox%x, %s, %s\n",
               offset,
               ' ',
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("\n----------------\n");
}
