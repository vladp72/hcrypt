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

void print(int offset, NCRYPT_SUPPORTED_LENGTHS const &key_name);

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
        printf("%*cname: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cblock length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cblock length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_chaining_mode(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cchaining mode: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cchaining mode: error code = 0x%x\n", offset, ' ', status.value());
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
        printf("%*cchaining mode: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_dh_parameters(&buffer_value);
    if (hcrypt::is_success(status)) {
        BCRYPT_DH_PARAMETER_HEADER *dh_parameter_header{
            reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER *>(buffer_value.data())};

        printf(
            "%*cDH parameter header: length %lu, magic 0x%lx, key length %lu\n",
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
        printf("%*cDH parameter header: error code = 0x%x\n", offset, ' ', status.value());
    }

    BCRYPT_DSA_PARAMETER_HEADER_V2 dsa_parameter_header{};
    status = obj.try_get_dsa_parameters(&dsa_parameter_header);
    if (hcrypt::is_success(status)) {
        printf("%*cDSA parameter header: length %lu, magic %lu, key length "
               "%lu, %ws, "
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
        printf("%*cDSA parameter header: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_effective_key_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ceffective key length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ceffective key length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_hash_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*chash block length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*chash block length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_hash_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*chash length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*chash length: error code = 0x%x\n", offset, ' ', status.value());
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
        printf("%*coid list: error code = 0x%x\n", offset, ' ', status.value());
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
        printf("%*ckey length: error code = 0x%x\n", offset, ' ', status.value());
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
        printf("%*ckeys length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_object_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey object length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey object length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_strength(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey strength: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*ckey strength: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_auth_tag_lengts(&keys_length);
    if (hcrypt::is_success(status)) {
        printf("%*cauth tag length: min %lu, max %lu, increment %lu\n",
               offset,
               ' ',
               keys_length.dwMinLength,
               keys_length.dwMaxLength,
               keys_length.dwIncrement);
    } else if (!hide_errors) {
        printf("%*cauth tag length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_message_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cmessage block length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cmessage block length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_multi_object_length(&buffer_value);
    if (hcrypt::is_success(status)) {
        BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const *multi_object_length{
            reinterpret_cast<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const *>(
                buffer_value.data())};

        printf(
            "%*cmulti object length: per object %lu, per element %lu, buffer "
            "%ws\n",
            offset,
            ' ',
            multi_object_length->cbPerObject,
            multi_object_length->cbPerElement,
            hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
        printf("%*cmulti object length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_dh_parameters(&buffer_value);
    if (hcrypt::is_success(status)) {
        BCRYPT_DH_PARAMETER_HEADER *dh_parameter_header{
            reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER *>(buffer_value.data())};

        printf(
            "%*cDH parameter header: length %lu, magic 0x%lx, key length %lu\n",
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
        printf("%*cDH parameter header: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_object_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cobject length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cobject length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_padding_schemes(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cpadding schemes: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cpadding schemes: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_signature_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*csignature length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*csignature length: error code = 0x%x\n", offset, ' ', status.value());
    }
}

template<typename T>
inline void print_ncrypt_object_properties(int offset, T &obj, bool hide_errors = false) {
    std::error_code status{hcrypt::status::success};

    std::wstring string_value;
    DWORD dword_value{0};
    unsigned long long ull_value{0};
    hcrypt::buffer buffer_value;
    FILETIME ft{0};

    status = obj.try_get_algorithm_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*calgorithm name: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*calgorithm name: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_associated_ecdh_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cecdh name: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cecdh name: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_block_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cblock length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cblock length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_certificate(&buffer_value);
    if (hcrypt::is_success(status)) {
        printf("%*ccertificate: %s\n",
               offset,
               ' ',
               hcrypt::to_base64(buffer_value.data(), buffer_value.size()).c_str());

    } else if (!hide_errors) {
        printf("%*ccertificate: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_export_policy(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cexport policy: %lx, %ws\n",
               offset,
               ' ',
               dword_value,
               ncrypt::export_policy_flags_to_string(dword_value).c_str());
    } else if (!hide_errors) {
        printf("%*cexport policy: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_implementation_flags(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cimplementation flags: %lx, %ws\n",
               offset,
               ' ',
               dword_value,
               ncrypt::implementation_flags_to_string(dword_value).c_str());
    } else if (!hide_errors) {
        printf("%*cimplementation flags: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_type(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey type: %lx, %ws\n",
               offset,
               ' ',
               dword_value,
               ncrypt::key_type_flags_to_string(dword_value).c_str());
    } else if (!hide_errors) {
        printf("%*ckey type: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_key_usage(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*ckey usage: %lx, %ws\n",
               offset,
               ' ',
               dword_value,
               ncrypt::key_usage_flags_to_string(dword_value).c_str());
    } else if (!hide_errors) {
        printf("%*ckey usage: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_last_modified(&ft);
    if (hcrypt::is_success(status)) {
        printf("%*clast modified: %s\n",
               offset,
               ' ',
               hcrypt::filetime_to_string(ft).c_str());
    } else if (!hide_errors) {
        printf("%*clast modified: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*clength: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*clength: error code = 0x%x\n", offset, ' ', status.value());
    }

    NCRYPT_SUPPORTED_LENGTHS supported_lengths;
    status = obj.try_get_supported_lengths(&supported_lengths);
    if (hcrypt::is_success(status)) {
        print(offset, supported_lengths);
    } else if (!hide_errors) {
        printf("%*csupported length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_max_name_length(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cmax name length: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cmax name length: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cname: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cname: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_security_descriptor_supported(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*csecurity descriptor supported: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*csecurity descriptor supported: error code = 0x%x\n",
               offset,
               ' ',
               status.value());
    }

    status = obj.try_get_security_descriptor(&buffer_value);
    if (hcrypt::is_success(status)) {
        printf("%*csecurity descriptor: %ws\n",
               offset,
               ' ',
               hcrypt::to_hex(buffer_value).c_str());

    } else if (!hide_errors) {
        printf("%*ccertificate: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_ui_policy(&buffer_value);
    if (hcrypt::is_success(status)) {
        NCRYPT_UI_POLICY *ui_policy{
            reinterpret_cast<NCRYPT_UI_POLICY *>(buffer_value.data())};

        printf(
            "%*cUI Policy: version %lu, magic 0x%lx, title \"%ws\", friendly "
            "name \"%ws\", descrption \"%ws\"\n",
            offset,
            ' ',
            ui_policy->dwVersion,
            ui_policy->dwFlags,
            ui_policy->pszCreationTitle,
            ui_policy->pszFriendlyName,
            ui_policy->pszDescription);
    } else if (!hide_errors) {
        printf("%*cUI Policy: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_uniqie_name(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cunique name: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cunique name: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_use_context(&string_value);
    if (hcrypt::is_success(status)) {
        printf("%*cuse context: %ws\n", offset, ' ', string_value.c_str());
    } else if (!hide_errors) {
        printf("%*cuse context: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_use_count_enabled(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cuse count enabled: %lu\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cuse count enabled: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_use_count(&ull_value);
    if (hcrypt::is_success(status)) {
        printf("%*cuse count: %llu\n", offset, ' ', ull_value);
    } else if (!hide_errors) {
        printf("%*cuse count: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_version(&dword_value);
    if (hcrypt::is_success(status)) {
        printf("%*cversion: %lu, 0x%lx\n", offset, ' ', dword_value, dword_value);
    } else if (!hide_errors) {
        printf("%*cversion: error code = 0x%x\n", offset, ' ', status.value());
    }

    HWND wnd{nullptr};
    status = obj.try_get_hwnd(&wnd);
    if (hcrypt::is_success(status)) {
        printf("%*cHWND: %lx\n", offset, ' ', dword_value);
    } else if (!hide_errors) {
        printf("%*cHWND: error code = 0x%x\n", offset, ' ', status.value());
    }

    ncrypt::storage_provider provider;
    status = obj.try_get_storage_provider(&provider);
    if (hcrypt::is_success(status)) {
        printf("%*cprovider handle: %zx\n", offset, ' ', provider.get_handle());
    } else if (!hide_errors) {
        printf("%*cprovider handle: error code = 0x%x\n", offset, ' ', status.value());
    }

    ncrypt::pin_id pin_id{0};
    status = obj.try_get_pin_id(&pin_id);
    if (hcrypt::is_success(status)) {
        printf("%*cpin id: %lx\n", offset, ' ', pin_id);
    } else if (!hide_errors) {
        printf("%*cpin id: error code = 0x%x\n", offset, ' ', status.value());
    }

    PIN_INFO pin_info{};
    status = obj.try_get_pin_info(&pin_info);
    if (hcrypt::is_success(status)) {
        printf("%*cpin info: ver 0x%lx, type %ws, purpose %ws, change permissions 0x%lx, unblock permissions 0x%lx, flags 0x%x, cache policy ver 0x%lx, cache policy info 0x%lx, cache policy type %ws\n",
               offset,
               ' ',
               pin_info.dwVersion,
               ncrypt::secret_type_to_string(pin_info.PinType),
               ncrypt::secret_purpose_to_string(pin_info.PinPurpose),
               pin_info.dwChangePermission,
               pin_info.dwUnblockPermission,
               pin_info.dwFlags,
               pin_info.PinCachePolicy.dwVersion,
               pin_info.PinCachePolicy.dwPinCachePolicyInfo,
               ncrypt::pin_cache_policy_type_to_string(pin_info.PinCachePolicy.PinCachePolicyType));
    } else if (!hide_errors) {
        printf("%*cpin info: error code = 0x%x\n", offset, ' ', status.value());
    }

    HCERTSTORE cert_store{nullptr};
    status = obj.try_get_root_certificate_store(&cert_store);
    if (hcrypt::is_success(status)) {
        BCRYPT_CODDING_ERROR_IF_NOT(CertCloseStore(cert_store, 0));
        printf("%*croot cert store: %p\n", offset, ' ', cert_store);
    } else if (!hide_errors) {
        printf("%*croot cert store: error code = 0x%x\n", offset, ' ', status.value());
    }

    status = obj.try_get_user_certificate_store(&cert_store);
    if (hcrypt::is_success(status)) {
        BCRYPT_CODDING_ERROR_IF_NOT(CertCloseStore(cert_store, 0));
        printf("%*cuser cert store: %p\n", offset, ' ', cert_store);
    } else if (!hide_errors) {
        printf("%*cuser cert store: error code = 0x%x\n", offset, ' ', status.value());    
    }

   GUID guid{};
    status = obj.try_get_smartcard_guid(&guid);
    if (hcrypt::is_success(status)) {
        printf("%*csmartcard GUID: {%s}\n", offset, ' ', hcrypt::guid_to_string(guid).c_str());
    } else if (!hide_errors) {
        printf("%*csmartcard GUID: error code = 0x%x\n", offset, ' ', status.value());
    }
}
