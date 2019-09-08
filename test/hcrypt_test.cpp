// bcryptlib.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include "hbcrypt.h"


void print(int offset, CRYPT_INTERFACE_REG const* interface_registartion) {
    printf("%*cinterface = %u, %ws\n", 
           offset, 
           ' ', 
           interface_registartion->dwInterface, 
           bcrypt::interface_id_to_string(interface_registartion->dwInterface));
    printf("%*cflags     = %u %ws\n", 
           offset, 
           ' ', 
           interface_registartion->dwFlags,
           bcrypt::interface_flags_to_string(interface_registartion->dwFlags).c_str());
    for (ULONG idx = 0; idx < interface_registartion->cFunctions; ++idx) {
        printf("%*cfunction: %ws\n", 
               offset + 2, 
               ' ', 
               interface_registartion->rgpszFunctions[idx]);
    }
}

void print(int offset, CRYPT_IMAGE_REG const* registartion) {
    printf("%*cimage: %ws\n", offset, ' ', registartion->pszImage);
    for (ULONG idx = 0; idx < registartion->cInterfaces; ++idx) {
        print(offset + 2, registartion->rgpInterfaces[idx]);
    }
}

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
        printf("%*cError code = %#x, %s\n", offset + 2, ' ', ex.code().value(), ex.what());
    }
}

void print(int offset, CRYPT_PROPERTY_REF const* property_ref) {
    printf("%*cproperty: %ws, bytes %u", 
           offset, 
           ' ', 
           property_ref->pszProperty,
           property_ref->cbValue);

    if (4 == property_ref->cbValue) {
        printf(", value %u", *reinterpret_cast<ULONG const *>(property_ref->pbValue));
    }
    printf("\n");
}

void print(int offset, CRYPT_IMAGE_REF const* image_ref) {
    printf("%*cimage: %ws, flags 0x%x, %ws\n", 
           offset, 
           ' ', 
           image_ref->pszImage,
           image_ref->dwFlags,
           bcrypt::image_flags_to_string(image_ref->dwFlags).c_str());
}

void print(int offset,
           CRYPT_PROVIDER_REF const *provider_ref) {
    printf("%*cprovider: %ws, function - %ws; itf - %u, %ws\n", 
           offset, 
           ' ', 
           provider_ref->pszProvider, 
           provider_ref->pszFunction,
           provider_ref->dwInterface,
           bcrypt::interface_id_to_string(provider_ref->dwInterface));
        
    for (ULONG idx = 0; idx < provider_ref->cProperties; ++idx) {
        print(offset + 2, provider_ref->rgpProperties[idx]);
    }

    if (provider_ref->pUM) {
        print(offset + 2, provider_ref->pUM);
    }

    if (provider_ref->pKM) {
        print(offset + 2, provider_ref->pKM);
    }
}

void print(int offset, CRYPT_PROVIDER_REFS const* interface_registartion_ref) {

    for (ULONG idx = 0; idx < interface_registartion_ref->cProviders; ++idx) {
        print(offset + 2, interface_registartion_ref->rgpProviders[idx]);
    }
}

void print(int offset, BCRYPT_ALGORITHM_IDENTIFIER const* algorithm_info) {
    printf("%*cname: %ws, class %ws, flags 0x%x\n",
        offset,
        ' ',
        algorithm_info->pszName,
        bcrypt::interface_id_to_string(algorithm_info->dwClass),
        algorithm_info->dwFlags);
}

void print(int offset, bcrypt::crypto_context_function_cptr const& crypto_context_functions) {
    bcrypt::find_first(crypto_context_functions, [offset](wchar_t const* context_name) -> bool {
            printf("%*cfunction: %ws\n",
                   offset,
                   ' ',
                   context_name);

            return true;
        });
}

void print_crypto_context(int offset, ULONG table) {

    printf("%*ctable: %ws\n",
            offset,
            ' ',
            bcrypt::table_to_string(table));

    
    bcrypt::find_first(bcrypt::enum_crypto_context(table), 
        [offset = offset + 2, table](wchar_t const* context_name) -> bool {
            printf("%*ccontext: %ws\n",
                   offset,
                   ' ',
                   context_name);

            bcrypt::find_first_interface([offset = offset + 2, table, context_name](ULONG itf_id) -> bool {

                printf("%*cinterface: %ws\n",
                    offset,
                    ' ',
                    bcrypt::interface_id_to_string(itf_id));

                try {

                    bcrypt::find_first(bcrypt::enum_crypto_context_function(table,
                                                                            context_name,
                                                                            itf_id),
                                        [offset = offset + 2, table, context_name, itf_id](wchar_t const* function_name)->bool {
                                            printf("%*cfunction: %ws\n",
                                                   offset,
                                                   ' ',
                                                   function_name);

                                            try {

                                                bcrypt::find_first(bcrypt::enum_crypto_context_function_providers(table, 
                                                                                                                  context_name,
                                                                                                                  itf_id,
                                                                                                                  function_name),
                                                    [offset = offset + 2](wchar_t const *provider_name)->bool {
                                                        printf("%*cprovider: %ws\n",
                                                               offset,
                                                               ' ',
                                                               provider_name);
                                                    return true;
                                                    });

                                            } catch (std::system_error const& ex) {
                                                printf("% *cenum_crypto_context_function, error code = %u, %s\n",
                                                       offset,
                                                       ' ',
                                                       ex.code().value(),
                                                       ex.what());
                                            }


                                            return true;
                                        });

                } catch (std::system_error const& ex) {
                    printf("% *cenum_crypto_context_function, error code = %u, %s\n",
                            offset,
                            ' ',
                            ex.code().value(),
                            ex.what());
                }
                return true;
            });
            return true;
        });
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
        printf("print_registered_providers, error code = %u, %s\n", 
               ex.code().value(), 
               ex.what());
    }
    printf("----------------\n");
}

void resolve_providers() {
    try {
        int offset{ 0 };

        printf("---Looking up provider by interface---------------\n");

        bcrypt::find_first_interface([offset = offset + 2](ULONG itf_id) -> bool {
                try {

                    printf("%*c--Querying itf - %u, %ws\n",
                           offset,
                           ' ',
                           itf_id,
                          bcrypt::interface_id_to_string(itf_id));

                    bcrypt::provider_registration_refs_cptr matching_providers{ bcrypt::resolve_providers(nullptr,
                                                                                                         itf_id,
                                                                                                         nullptr,
                                                                                                         nullptr,
                                                                                                         CRYPT_UM,
                                                                                                         CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS) };

                    bcrypt::find_first(matching_providers, [offset](CRYPT_PROVIDER_REF const *provider_ref) -> bool {
                            print(offset + 2, provider_ref);
                            return true;
                        });

                } catch (std::system_error const& ex) {
                    printf("%*cError code = %#x, %s\n", 
                           offset + 2, 
                           ' ', 
                           ex.code().value(), 
                           ex.what());
                }

                return true;
            });

    } catch (std::system_error const& ex) {
        printf("resolve_providers, error code = %u, %s\n", 
               ex.code().value(), 
               ex.what());
    }
    printf("----------------\n");
}

void print_algorithms(int offset, ULONG ciypher_operations) {
    try {
        printf("%*c--Querying algorithms for cipher operations - %u, %ws\n",
               offset,
               ' ',
               ciypher_operations,
               bcrypt::algorithm_operations_to_string(ciypher_operations).c_str());

        bcrypt::find_first(bcrypt::enum_algorithms(ciypher_operations),
                        [offset](BCRYPT_ALGORITHM_IDENTIFIER const& algorithm_info) -> bool {
                            print(offset + 2, &algorithm_info);
                            return true;
                        });

    } catch (std::system_error const& ex) {
        printf("print_algorithms, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
}

void print_algorithms() {
    try {
        int offset{ 0 };

        printf("---Enumirating algorithms---------------\n");

        ULONG ciypher_operations{ BCRYPT_CIPHER_OPERATION |
                                  BCRYPT_HASH_OPERATION |
                                  BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
                                  BCRYPT_SECRET_AGREEMENT_OPERATION |
                                  BCRYPT_SIGNATURE_OPERATION |
                                  BCRYPT_RNG_OPERATION };

        print_algorithms(offset + 2, ciypher_operations);
    } catch (std::system_error const& ex) {
        printf("resolve_providers, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}

void print_crypto_contexts() {
    try {
        int offset{ 0 };

        printf("---Enumirating crypto contexts---------------\n");

        print_crypto_context(offset + 2, CRYPT_LOCAL);
        print_crypto_context(offset + 2, CRYPT_DOMAIN);

    } catch (std::system_error const& ex) {
        printf("print_crypto_contexts, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}

void print_is_fips_complience_on() {
    try {
        int offset{ 0 };

        printf("---Query FIPS complience---------------\n");

        bool fips_complience_on{ bcrypt::is_fips_complience_on() };

        printf("FIPS  complience on = %s\n", 
               fips_complience_on ? "Yes" : "No");
    } catch (std::system_error const& ex) {
        printf("is_fips_complience_on, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}

void test_CTAD() {

    bcrypt::buffer_ptr void_ptr;
    static_assert(std::is_same_v<decltype(void_ptr), bcrypt::buffer_ptr<void>>);
    bcrypt::buffer_ptr void_ptr2( std::move(void_ptr) );
    static_assert(std::is_same_v<decltype(void_ptr2), bcrypt::buffer_ptr<void>>);

    int* p{ nullptr };

    bcrypt::buffer_ptr int_ptr(p);
    static_assert(std::is_same_v<decltype(int_ptr), bcrypt::buffer_ptr<int>>);
}

template<typename T>
void print_object_properties(int offset, T &obj) {

    NTSTATUS status{ STATUS_SUCCESS };
    
    std::wstring string_value;
    DWORD dword_value{ 0 };
    bcrypt::buffer buffer_value;
    
    status = obj.try_get_name(&string_value);
    if (NT_SUCCESS(status)) {
        printf("%*cname: %ws\n", 
               offset,
               ' ',
               string_value.c_str());
    } else {
        printf("%*cname: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_block_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*cblock length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*cblock length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_chaining_mode(&string_value);
    if (NT_SUCCESS(status)) {
        printf("%*cchaining mode: %ws\n", 
               offset,
               ' ',
               string_value.c_str());
    } else {
        printf("%*cchaining mode: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_block_size_list(&buffer_value);
    if (NT_SUCCESS(status)) {
        DWORD* block_size_cur{ reinterpret_cast<DWORD*>(buffer_value.data()) };
        DWORD* block_size_end{ reinterpret_cast<DWORD*>(buffer_value.data() + buffer_value.size()) };
        for (int idx{ 0 }; block_size_cur <= block_size_end; ++idx, ++block_size_cur) {
            printf("%*cblock[%02u] size: %u\n",
                offset,
                ' ',
                idx,
                *block_size_cur);
        };
    } else {
        printf("%*cchaining mode: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    BCRYPT_DH_PARAMETER_HEADER dh_parameter_header{};
    status = obj.try_get_dh_parameters(&dh_parameter_header);
    if (NT_SUCCESS(status)) {
        printf("%*cDH parameter header: length %u, magic %u, key length %u\n", 
               offset,
               ' ',
               dh_parameter_header.cbLength,
               dh_parameter_header.dwMagic,
               dh_parameter_header.cbKeyLength);
    } else {
        printf("%*cDH parameter header: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    BCRYPT_DSA_PARAMETER_HEADER_V2 dsa_parameter_header{};
    status = obj.try_get_dsa_parameters(&dsa_parameter_header);
    if (NT_SUCCESS(status)) {
        printf("%*cDSA parameter header: length %u, magic %u, key length %u, %ws, %ws, seed length %u, group size %u, count{%u, %u, %u, %u}\n", 
               offset,
               ' ',
               dsa_parameter_header.cbLength,
               dsa_parameter_header.dwMagic,
               dsa_parameter_header.cbKeyLength,
               bcrypt::dsa_algorithm_to_string(dsa_parameter_header.hashAlgorithm),
               bcrypt::dsa_fips_version_to_string(dsa_parameter_header.standardVersion), 
               dsa_parameter_header.cbSeedLength,
               dsa_parameter_header.cbGroupSize,
               static_cast<int>(dsa_parameter_header.Count[0]),
               static_cast<int>(dsa_parameter_header.Count[1]),
               static_cast<int>(dsa_parameter_header.Count[2]),
               static_cast<int>(dsa_parameter_header.Count[3]));
    } else {
        printf("%*cDSA parameter header: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_effective_key_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*ceffective key length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*ceffective key length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_hash_block_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*chash block length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*chash block length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_hash_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*chash length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*chash length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_oid_list(&buffer_value);
    if (NT_SUCCESS(status)) {
        if (buffer_value.size() >= sizeof(BCRYPT_OID_LIST)) {
            
            bcrypt::find_first(reinterpret_cast<BCRYPT_OID_LIST*>(buffer_value.data()), 
                                [offset = offset + 2](BCRYPT_OID const& oid) -> bool {

                                    printf("%*cblock size: %u, value: %ws\n",
                                           offset,
                                           ' ',
                                           oid.cbOID,
                                           bcrypt::to_hex(oid.pbOID, oid.pbOID + oid.cbOID).c_str());

                                    return true;
                                });
        } else {
            printf("%*coid list size is too small: %Iu\n", 
                   offset,
                   ' ',
                   buffer_value.size());;
        }
    } else {
        printf("%*coid list: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_initialization_vector(&buffer_value);
    if (NT_SUCCESS(status)) {

        printf("%*cinitialization vector: %ws\n",
                offset,
                ' ',
                bcrypt::to_hex(buffer_value).c_str());

    } else {
        printf("%*cinitialization vector: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_key_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*ckey length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*ckey length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    BCRYPT_KEY_LENGTHS_STRUCT keys_length{};
    status = obj.try_get_key_lengts(&keys_length);
    if (NT_SUCCESS(status)) {
        printf("%*ckeys length: min %u, max %u, increment %u\n", 
               offset,
               ' ',
               keys_length.dwMinLength,
               keys_length.dwMaxLength,
               keys_length.dwIncrement);
    } else {
        printf("%*ckeys length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_key_object_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*ckey object length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*ckey object length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_key_strength(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*ckey strength: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*ckey strength: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_message_block_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*cmessage block length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*cmessage block length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_multi_object_length(&buffer_value);
    if (NT_SUCCESS(status)) {

        BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const* multi_object_length{ 
            reinterpret_cast<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const*>(buffer_value.data()) };

        printf("%*cmulti object length: per object %u, per element %u, buffer %ws\n",
                offset,
                ' ',
                multi_object_length->cbPerObject,
                multi_object_length->cbPerElement,
                bcrypt::to_hex(buffer_value).c_str());

    } else {
        printf("%*cmulti object length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

   status = obj.try_get_object_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*cobject length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*cobject length: error code = %x\n", 
               offset,
               ' ',
               status);
    }

   status = obj.try_get_padding_schemes(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*cpadding schemes: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*cpadding schemes: error code = %x\n", 
               offset,
               ' ',
               status);
    }

   status = obj.try_get_signature_length(&dword_value);
    if (NT_SUCCESS(status)) {
        printf("%*csignature length: %u\n", 
               offset,
               ' ',
               dword_value);
    } else {
        printf("%*csignature length: error code = %x\n", 
               offset,
               ' ',
               status);
    }
}

void test_algorithm() {
    printf("---Testing bcrypt::algorithm_provider---------------\n");
    try {

        int offset{ 0 };

        NTSTATUS status{ STATUS_SUCCESS };

        bcrypt::algorithm_provider ap;

        ap.open(BCRYPT_AES_ALGORITHM);

        print_object_properties(offset + 2, ap);


    } catch (std::system_error const& ex) {
        printf("test_algorithm, error code = %u, %s\n",
            ex.code().value(),
            ex.what());
    }
    printf("----------------\n");
}

int main() {

    test_CTAD();

    try {
        int offset{ 0 };

        //print_is_fips_complience_on();

        //print_registered_providers();

        //resolve_providers();

        //print_algorithms();

        //print_crypto_contexts();

        test_algorithm();

    } catch (std::system_error const& ex) {
        printf("Error code = %u, %s\n", ex.code().value(), ex.what());
    }
}

