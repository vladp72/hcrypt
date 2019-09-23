#include "hbcrypt_test_registered_providers.h"

void print_provider_interface_info(int offset,
                                   wchar_t const *provider_name,
                                   ULONG mode,
                                   ULONG itf_id) {
    printf("%*cprovider: %ws, mode - %u, %ws; itf - %u, %ws\n", 
           offset, 
           ' ', 
           provider_name, 
           mode, 
           bcrypt::provider_mode_to_string(mode),
           itf_id,
           bcrypt::interface_id_to_string(itf_id));
    try {
        bcrypt::provider_registration_cptr registration{ bcrypt::query_provider_registartion(provider_name,
                                                                                             mode,
                                                                                             itf_id) };
        if (registration) {
            for (ULONG idx = 0; idx < registration->cAliases; ++idx) {
                printf("%*calias: %ws\n", offset + 2, ' ', registration->rgpszAliases[idx]);
            }

            if (registration->pUM) {
                print(offset + 2, registration->pUM);
            }

            if (registration->pKM) {
                print(offset + 2, registration->pKM);
            }
        }
    } catch (std::system_error const& ex) {
        printf("%*cError code = %#x, %s, %s\n", 
               offset + 2, 
               ' ', 
               ex.code().value(), 
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
}

void print_registered_providers() {
    try {
        int offset{ 0 };

        printf("----------------\n");
        bcrypt::providers_cptr providers{ bcrypt::enum_registered_providers() };

        bcrypt::find_first(providers, [offset](wchar_t  const* provider_name) -> bool {
                printf("%*cprovider: %ws\n", offset, ' ', provider_name);
                
                printf("--UM--------------\n");

                bcrypt::find_first_interface([offset, provider_name](ULONG itf_id) -> bool {
                        print_provider_interface_info(offset + 2, 
                                                      provider_name, 
                                                      CRYPT_UM, 
                                                      itf_id);
                        return true;
                    });

                printf("--KM--------------\n");


                bcrypt::find_first_interface([offset, provider_name](ULONG itf_id) -> bool {
                        print_provider_interface_info(offset + 2, 
                                                      provider_name, 
                                                      CRYPT_KM, 
                                                      itf_id);
                        return true;
                    });

                return true;
            });
    } catch (std::system_error const& ex) {
        printf("print_registered_providers, error code = 0x%x, %s, %s\n", 
               ex.code().value(), 
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("----------------\n");
}