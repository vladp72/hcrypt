#include "hbcrypt_test_resolve_providers.hpp"

void resolve_providers() {
    try {
        int offset{0};

        printf("---Looking up provider by interface---------------\n");

        bcrypt::find_first_interface([offset = offset + 2](ULONG itf_id) -> bool {
            try {
                printf("%*c--Querying itf - %lu, %ws\n",
                       offset,
                       ' ',
                       itf_id,
                       bcrypt::interface_id_to_string(itf_id));

                bcrypt::provider_registration_refs_cptr matching_providers{bcrypt::resolve_providers(
                    nullptr, itf_id, nullptr, nullptr, CRYPT_UM, CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS)};

                bcrypt::find_first(matching_providers,
                                   [offset](CRYPT_PROVIDER_REF const *provider_ref) -> bool {
                                       print(offset + 2, provider_ref);
                                       return true;
                                   });

            } catch (std::system_error const &ex) {
                printf("%*cError code = %#x, %s\n", offset + 2, ' ', ex.code().value(), ex.what());
            }

            return true;
        });

    } catch (std::system_error const &ex) {
        printf("resolve_providers, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("----------------\n");
}
