#pragma once

#include <hbcrypt.hpp>
#include <hncrypt.hpp>

void print(int offset, CRYPT_INTERFACE_REG const *interface_registartion);

void print(int offset, CRYPT_IMAGE_REG const *registartion);

void print(int offset, CRYPT_PROPERTY_REF const *property_ref);

void print(int offset, CRYPT_IMAGE_REF const *image_ref);

void print(int offset, CRYPT_PROVIDER_REF const *provider_ref);

void print(int offset, CRYPT_PROVIDER_REFS const *interface_registartion_ref);

void print(int offset, BCRYPT_ALGORITHM_IDENTIFIER const *algorithm_info);

void print(int offset, bcrypt::crypto_context_function_cptr const &crypto_context_functions);

void print(int offset, NCryptKeyName const &key_name);

template<typename T>
inline void print_bcrypt_object_properties(int offset, T &obj, bool hide_errors = false) {
    std::error_code status{hcrypt::status::success};

    std::wstring string_value;
    DWORD dword_value{0};
    hcrypt::buffer buffer_value;

    status = obj.try_get_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cname: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cname: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cblock length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cblock length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_chaining_mode(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cchaining mode: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cchaining mode: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_block_size_list(&buffer_value);
    if (hcrypt::is_success(status)) {
        DWORD *block_size_cur{reinterpret_cast<DWORD *>(buffer_value.data())};
        DWORD *block_size_end{
            reinterpret_cast<DWORD *>(buffer_value.data() + buffer_value.size())};
        for (int idx{0}; block_size_cur <= block_size_end; ++idx, ++block_size_cur) {
            printf("%*cblock[%02u] size: %lu\n", offset, ' ', idx, *block_size_cur);
        };
    } else if (!hide_errors) {
        printf("%*cchaining mode: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_dh_parameters(&buffer_value);
    if (hcrypt::is_success(status)) {
        BCRYPT_DH_PARAMETER_HEADER *dh_parameter_header{
            reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER *>(buffer_value.data())};

        printf("%*cDH parameter header: length %lu, magic 0x%lx, key length %lu\n",
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
                                  buffer_value.end())
                       .c_str());
        }

    } else if (!hide_errors) {
        printf("%*cDH parameter header: error code = %x\n", offset, ' ', status.value());
    }

    BCRYPT_DSA_PARAMETER_HEADER_V2 dsa_parameter_header{};
    status = obj.try_get_dsa_parameters(&dsa_parameter_header);
    if (hcrypt::is_success(status)) {
        printf(
            "%*cDSA parameter header: length %lu, magic %lu, key length %lu, %ws, "
            "%ws, seed length %lu, group size %lu, count{%u, %u, %u, %u}\n",
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
        printf("%*cDSA parameter header: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_effective_key_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ceffective key length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ceffective key length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_hash_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*chash block length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*chash block length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_hash_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*chash length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*chash length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_oid_list(&buffer_value);
    if (hcrypt::is_success(status)) {
        if (buffer_value.size() >= sizeof(BCRYPT_OID_LIST)) {
            bcrypt::find_first(
                reinterpret_cast<BCRYPT_OID_LIST *>(buffer_value.data()),
                [offset = offset + 2](BCRYPT_OID const &oid) -> bool {
                    printf("%*cblock size: %lu, value: %ws\n",
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
                   buffer_value.size());
            ;
        }
    } else if (!hide_errors) {
        printf("%*coid list: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_initialization_vector(&buffer_value);
    if (hcrypt::is_success(status)) {
        printf("%*cinitialization vector: %ws\n",
               offset,
               ' ',
               hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
        printf(
            "%*cinitialization vector: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey length: error code = %x\n", offset, ' ', status.value());
    }

    BCRYPT_KEY_LENGTHS_STRUCT keys_length{};
    status = obj.try_get_key_lengts(&keys_length);
    if (hcrypt::is_success(status)) {
        printf("%*ckeys length: min %lu, max %lu, increment %lu\n",
               offset,
               ' ',
               keys_length.dwMinLength,
               keys_length.dwMaxLength,
               keys_length.dwIncrement);
    } else if (!hide_errors) {
        printf("%*ckeys length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_object_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey object length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey object length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_strength(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey strength: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey strength: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_message_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cmessage block length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cmessage block length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_multi_object_length(&buffer_value);
    if (hcrypt::is_success(status)) {
        BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const *multi_object_length{
            reinterpret_cast<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const *>(
                buffer_value.data())};

        printf("%*cmulti object length: per object %lu, per element %lu, buffer "
               "%ws\n",
               offset,
               ' ',
               multi_object_length->cbPerObject,
               multi_object_length->cbPerElement,
               hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
        printf("%*cmulti object length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_object_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cobject length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cobject length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_padding_schemes(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cpadding schemes: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cpadding schemes: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_signature_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*csignature length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*csignature length: error code = %x\n", offset, ' ', status.value());
    }
}

template<typename T>
inline void print_ncrypt_object_properties(int offset, T &obj, bool hide_errors = false) {
    std::error_code status{hcrypt::status::success};

    std::wstring string_value;
    DWORD dword_value{0};
    hcrypt::buffer buffer_value;

    status = obj.try_get_algorithm_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*calgorithm name: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*calgorithm name: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_associated_ecdh_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cecdh name: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cecdh name: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cblock length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cblock length: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_export_policy(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cexport policy: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cexport policy: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_implementation_flags(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cimplementation flags: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cimplementation flags: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_type(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey type: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey type: error code = %x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_usage(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey usage: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey usage: error code = %x\n", offset, ' ', status.value());
    }
}
