#pragma once

#include <hbcrypt.h>
#include <hncrypt.h>

void print(int offset, CRYPT_INTERFACE_REG const* interface_registartion);

void print(int offset, CRYPT_IMAGE_REG const* registartion);

void print(int offset, CRYPT_PROPERTY_REF const* property_ref);

void print(int offset, CRYPT_IMAGE_REF const* image_ref);

void print(int offset, CRYPT_PROVIDER_REF const *provider_ref);

void print(int offset, CRYPT_PROVIDER_REFS const* interface_registartion_ref);

void print(int offset, BCRYPT_ALGORITHM_IDENTIFIER const* algorithm_info);

void print(int offset, bcrypt::crypto_context_function_cptr const& crypto_context_functions);

template<typename T>
inline void print_object_properties(int offset, T &obj, bool hide_errors = false) {

    NTSTATUS status{ STATUS_SUCCESS };
    
    std::wstring string_value;
    DWORD dword_value{ 0 };
    hcrypt::buffer buffer_value;
    
    status = obj.try_get_name(&string_value);
    if (NT_SUCCESS(status)) {
        printf("%*cname: %ws\n", 
               offset,
               ' ',
               string_value.c_str());
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
        printf("%*cchaining mode: error code = %x\n", 
               offset,
               ' ',
               status);
    }

    status = obj.try_get_dh_parameters(&buffer_value);
    if (NT_SUCCESS(status)) {
        BCRYPT_DH_PARAMETER_HEADER* dh_parameter_header{ reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER*>(buffer_value.data()) };

        printf("%*cDH parameter header: length %u, magic 0x%x, key length %u\n", 
               offset,
               ' ',
               dh_parameter_header->cbLength,
               dh_parameter_header->dwMagic,
               dh_parameter_header->cbKeyLength);

        if (buffer_value.size() > sizeof(BCRYPT_DH_PARAMETER_HEADER)) {
            printf("%*cDH data: %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(buffer_value.begin() + sizeof(BCRYPT_DH_PARAMETER_HEADER), 
                                  buffer_value.end()).c_str());
        }

    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
                                           hcrypt::to_hex(oid.pbOID, oid.pbOID + oid.cbOID).c_str());

                                    return true;
                                });
        } else if (!hide_errors) {
            printf("%*coid list size is too small: %Iu\n", 
                   offset,
                   ' ',
                   buffer_value.size());;
        }
    } else if (!hide_errors) {
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
                hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
                hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
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
    } else if (!hide_errors) {
        printf("%*csignature length: error code = %x\n", 
               offset,
               ' ',
               status);
    }
}


