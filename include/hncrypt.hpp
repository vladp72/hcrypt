#pragma once

#include "hcrypt_common.hpp"
#include <ncrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

//
// Hack for missing cardmod.h
// Make sure to include cardmod.h
// before hncrypt.h
//
#ifndef __CARDMOD__H__ // cardmod.h

typedef DWORD PIN_SET, *PPIN_SET;

typedef enum {
    AlphaNumericPinType = 0,  // Regular PIN
    ExternalPinType,          // Biometric PIN
    ChallengeResponsePinType, // Challenge/Response PIN
    EmptyPinType              // No PIN
} SECRET_TYPE;

typedef enum {
    AuthenticationPin,   // Authentication PIN
    DigitalSignaturePin, // Digital Signature PIN
    EncryptionPin,       // Encryption PIN
    NonRepudiationPin,   // Non Repudiation PIN
    AdministratorPin,    // Administrator PIN
    PrimaryCardPin,      // Primary Card PIN
    UnblockOnlyPin       // Unblock only PIN (PUK)
} SECRET_PURPOSE;

typedef enum {
    PinCacheNormal = 0,
    PinCacheTimed,
    PinCacheNone,
    PinCacheAlwaysPrompt
} PIN_CACHE_POLICY_TYPE;

typedef struct _PIN_CACHE_POLICY {
    DWORD dwVersion;
    PIN_CACHE_POLICY_TYPE PinCachePolicyType;
    DWORD dwPinCachePolicyInfo;
} PIN_CACHE_POLICY, *PPIN_CACHE_POLICY;

#define PIN_INFO_CURRENT_VERSION 6

#define PIN_INFO_REQUIRE_SECURE_ENTRY 1

typedef struct _PIN_INFO {
    DWORD dwVersion;
    SECRET_TYPE PinType;
    SECRET_PURPOSE PinPurpose;
    PIN_SET dwChangePermission;
    PIN_SET dwUnblockPermission;
    PIN_CACHE_POLICY PinCachePolicy;
    DWORD dwFlags;
} PIN_INFO, *PPIN_INFO;

#endif //__CARDMOD__H__

namespace ncrypt {

    using pin_id = unsigned long;

    template<typename T>
    class buffer_ptr final {
    public:
        using value_type = T;
        using mutable_value_type = std::remove_const_t<T>;
        constexpr static bool is_void{std::is_void_v<std::remove_cv_t<T>>};
        using reference_type =
            std::conditional_t<is_void, void, std::add_lvalue_reference_t<T>>;
        using pointer_type = T *;
        using mutable_pointer_type = mutable_value_type *;

        buffer_ptr() noexcept = default;

        buffer_ptr(pointer_type p) noexcept
            : p_(p) {
        }

        buffer_ptr(buffer_ptr const &) noexcept = delete;
        buffer_ptr &operator=(buffer_ptr const &) noexcept = delete;

        buffer_ptr(buffer_ptr &&other) noexcept
            : p_{other.detach()} {
        }

        buffer_ptr &operator=(buffer_ptr &&other) noexcept {
            if (this != &other) {
                free();
                p_ = other.detach();
            }
            return *this;
        }

        ~buffer_ptr() noexcept {
            free();
        }

        void swap(buffer_ptr &other) noexcept {
            pointer_type p{p_};
            p_ = other.p_;
            other.p_ = p;
        }

        pointer_type get() const noexcept {
            return p_;
        }

        reference_type operator*() const noexcept {
            return *p_;
        }

        pointer_type operator->() const noexcept {
            return p_;
        }

        void free() noexcept {
            if (p_) {
                NCryptFreeBuffer(const_cast<mutable_pointer_type>(p_));
                p_ = nullptr;
            }
        }

        [[nodiscard]] pointer_type detach() noexcept {
            pointer_type p{p_};
            p_ = nullptr;
            return p;
        }

        void attach(pointer_type p) noexcept {
            free();
            p_ = p;
        }

        explicit operator bool() const noexcept {
            return p_ != nullptr;
        }

    private:
        pointer_type p_{nullptr};
    };

    template<typename T>
    inline void swap(buffer_ptr<T> first, buffer_ptr<T> second) noexcept {
        first.swap(second);
    }

    using providers_cptr = buffer_ptr<NCryptProviderName const>;
    using providers_t = std::pair<providers_cptr, unsigned long>;

    [[nodiscard]] inline std::error_code try_enum_providers(providers_t *providers) noexcept {
        NCryptProviderName *providers_buffer{nullptr};
        unsigned long providers_count{0};
        hcrypt::status err{NCryptEnumStorageProviders(&providers_count, &providers_buffer, 0)};
        if (hcrypt::is_success(err)) {
            providers->first.attach(providers_buffer);
            providers->second = providers_count;
        }
        return err;
    }

    inline providers_t const enum_providers() {
        providers_t providers;
        std::error_code err{try_enum_providers(&providers)};
        if (hcrypt::is_failure(err)) {
            throw std::system_error(err, "NCryptEnumStorageProviders failed");
        }
        return providers;
    }

    template<typename FN>
    inline void find_first(providers_t const &providers, FN &&fn) {
        auto const &[buffer, element_count] = providers;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            if (!fn(buffer.get()[idx])) {
                break;
            }
        }
    }

    template<typename FN>
    inline void for_each(providers_t const &providers, FN &&fn) {
        auto const &[buffer, element_count] = providers;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            fn(buffer.get()[idx]);
        }
    }

    using algorithm_name_cptr = buffer_ptr<NCryptAlgorithmName const>;
    using algorithm_name_t = std::pair<algorithm_name_cptr, unsigned long>;

    template<typename FN>
    inline void find_first(algorithm_name_t const &algorithms, FN &&fn) {
        auto const &[buffer, element_count] = algorithms;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            if (!fn(buffer.get()[idx])) {
                break;
            }
        }
    }

    template<typename FN>
    inline void for_each(algorithm_name_t const &algorithms, FN &&fn) {
        auto const &[buffer, element_count] = algorithms;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            fn(buffer.get()[idx]);
        }
    }

    using key_name_cptr = buffer_ptr<NCryptKeyName const>;

    inline std::wstring legacy_key_spec_to_string(unsigned long legacy_key_spec) {
        std::wstring str;
        if (hcrypt::consume_flag(&legacy_key_spec, static_cast<unsigned long>(AT_KEYEXCHANGE))) {
            hcrypt::append_with_separator(&str, L" | ", L"AT_KEYEXCHANGE");
        }
        if (hcrypt::consume_flag(&legacy_key_spec, static_cast<unsigned long>(AT_SIGNATURE))) {
            hcrypt::append_with_separator(&str, L" | ", L"AT_SIGNATURE");
        }
        if (legacy_key_spec) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", legacy_key_spec).c_str());
        }
        return str;
    }

    inline std::wstring key_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_MACHINE_KEY_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_MACHINE_KEY_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring export_policy_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_EXPORT_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_EXPORT_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_ARCHIVING_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_ARCHIVING_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring implementation_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_IMPL_HARDWARE_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_IMPL_HARDWARE_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_IMPL_SOFTWARE_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_IMPL_SOFTWARE_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_IMPL_REMOVABLE_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_IMPL_REMOVABLE_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_IMPL_HARDWARE_RNG_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_IMPL_HARDWARE_RNG_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring key_type_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_MACHINE_KEY_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_MACHINE_KEY_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring key_usage_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_ALL_USAGES))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_ALL_USAGES");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_DECRYPT_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_DECRYPT_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_SIGNING_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_SIGNING_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_ALLOW_KEY_AGREEMENT_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_ALLOW_KEY_AGREEMENT_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring ui_protect_flags_to_string(unsigned long key_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_UI_PROTECT_KEY_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_UI_PROTECT_KEY_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG");
        }
        if (hcrypt::consume_flag(
                &key_flags, static_cast<unsigned long>(NCRYPT_UI_APPCONTAINER_ACCESS_MEDIUM_FLAG))) {
            hcrypt::append_with_separator(
                &str, L" | ", L"NCRYPT_UI_APPCONTAINER_ACCESS_MEDIUM_FLAG");
        }
        if (key_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", key_flags).c_str());
        }
        return str;
    }

    inline std::wstring enum_flags_to_string(unsigned long enum_flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &enum_flags, static_cast<unsigned long>(NCRYPT_MACHINE_KEY_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_MACHINE_KEY_FLAG");
        }
        if (hcrypt::consume_flag(&enum_flags, static_cast<unsigned long>(NCRYPT_SILENT_FLAG))) {
            hcrypt::append_with_separator(&str, L" | ", L"NCRYPT_SILENT_FLAG");
        }
        if (enum_flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", enum_flags).c_str());
        }
        return str;
    }

    constexpr inline wchar_t const *secret_type_to_string(SECRET_TYPE secret_type) {
        wchar_t const *secret_type_name{L"unknown secret type"};
        switch (secret_type) {
        case AlphaNumericPinType:
            secret_type_name = L"AlphaNumericPinType";
            break;
        case ExternalPinType:
            secret_type_name = L"ExternalPinType";
            break;
        case ChallengeResponsePinType:
            secret_type_name = L"ChallengeResponsePinType";
            break;
        case EmptyPinType:
            secret_type_name = L"EmptyPinType";
            break;
        }
        return secret_type_name;
    }

    constexpr inline wchar_t const *secret_purpose_to_string(SECRET_PURPOSE secret_purpose) {
        wchar_t const *secret_purpose_name{L"unknown secret purpose"};
        switch (secret_purpose) {
        case AuthenticationPin:
            secret_purpose_name = L"AuthenticationPin";
            break;
        case DigitalSignaturePin:
            secret_purpose_name = L"DigitalSignaturePin";
            break;
        case EncryptionPin:
            secret_purpose_name = L"EncryptionPin";
            break;
        case NonRepudiationPin:
            secret_purpose_name = L"NonRepudiationPin";
            break;
        case AdministratorPin:
            secret_purpose_name = L"AdministratorPin";
            break;
        case PrimaryCardPin:
            secret_purpose_name = L"PrimaryCardPin";
            break;
        case UnblockOnlyPin:
            secret_purpose_name = L"UnblockOnlyPin";
            break;
        }
        return secret_purpose_name;
    }

    constexpr inline wchar_t const *pin_cache_policy_type_to_string(PIN_CACHE_POLICY_TYPE pin_cache_policy_type) {
        wchar_t const *pin_cache_policy_type_name{L"unknown secret type"};
        switch (pin_cache_policy_type) {
        case PinCacheNormal:
            pin_cache_policy_type_name = L"PinCacheNormal";
            break;
        case PinCacheTimed:
            pin_cache_policy_type_name = L"PinCacheTimed";
            break;
        case PinCacheNone:
            pin_cache_policy_type_name = L"PinCacheNone";
            break;
        case PinCacheAlwaysPrompt:
            pin_cache_policy_type_name = L"PinCacheAlwaysPrompt";
            break;
        }
        return pin_cache_policy_type_name;
    }

    class key;
    class secret;
    class storage_provider;

    template<typename T>
    struct property_impl {
    protected:
        [[nodiscard]] std::error_code try_get_property(wchar_t const *property_name,
                                                       char *buffer,
                                                       size_t buffer_size,
                                                       size_t *rezult_size) const noexcept {
            unsigned long tmp_rezult_size{0};
            std::error_code status{hcrypt::nte_error_to_status(
                NCryptGetProperty(get_object_handle(),
                                  property_name,
                                  reinterpret_cast<unsigned char *>(buffer),
                                  static_cast<unsigned long>(buffer_size),
                                  &tmp_rezult_size,
                                  0))};
            *rezult_size = tmp_rezult_size;
            return status;
        }

        [[nodiscard]] std::error_code try_get_property(wchar_t const *property_name,
                                                       hcrypt::buffer *buffer) const noexcept {
            std::error_code status{hcrypt::status::success};
            for (;;) {
                size_t rezult_size{0};
                bool empty_buffer{buffer->empty()};
                status = try_get_property(property_name,
                                          empty_buffer ? nullptr : buffer->data(),
                                          empty_buffer ? 0 : buffer->size(),
                                          &rezult_size);
                if (hcrypt::is_success(status)) {
                    if (rezult_size <= buffer->size()) {
                        status = hcrypt::try_resize(buffer, rezult_size);
                        break;
                    } else {
                        status = hcrypt::try_resize(buffer, rezult_size);
                    }
                } else if (hcrypt::status::buffer_too_small == status) {
                    status = hcrypt::try_resize(buffer, rezult_size);
                } else {
                    break;
                }
            }
            return status;
        }

        [[nodiscard]] std::error_code try_get_property(wchar_t const *property_name,
                                                       std::wstring *buffer) const noexcept {
            std::error_code status{hcrypt::status::success};

            for (;;) {
                size_t rezult_size{0};
                bool empty_buffer{buffer->empty()};
                status = try_get_property(
                    property_name,
                    empty_buffer ? nullptr : reinterpret_cast<char *>(buffer->data()),
                    empty_buffer ? 0 : buffer->size() * sizeof(wchar_t),
                    &rezult_size);
                if (hcrypt::is_success(status)) {
                    if (rezult_size <= (buffer->size() * sizeof(wchar_t))) {
                        //
                        // Remove extra terminating 0
                        //
                        status = hcrypt::try_resize(
                            buffer, (rezult_size / sizeof(wchar_t)) - 1);
                        break;
                    } else {
                        status = hcrypt::try_resize(
                            buffer, (rezult_size / sizeof(wchar_t)));
                    }
                } else if (hcrypt::status::buffer_too_small == status) {
                    status = hcrypt::try_resize(buffer, rezult_size / sizeof(wchar_t));
                } else {
                    break;
                }
            }
            return status;
        }

        template<typename T>
        [[nodiscard]] std::error_code try_get_property(wchar_t const *property_name,
                                                       T *value,
                                                       size_t *result_size = nullptr) const
            noexcept {
            static_assert(std::is_pod_v<T>);
            size_t tmp_result_size{0};
            std::error_code status{try_get_property(
                property_name, reinterpret_cast<char *>(value), sizeof(*value), &tmp_result_size)};
            BCRYPT_CODDING_ERROR_IF(sizeof(*value) < tmp_result_size);
            if (result_size) {
                *result_size = tmp_result_size;
            }
            return status;
        }

        hcrypt::buffer get_property_as_buffer(wchar_t const *property_name,
                                              size_t default_buffer_size = 256) const {
            hcrypt::buffer b(default_buffer_size);
            std::error_code status{try_get_property(property_name, &b)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return b;
        }

        std::wstring get_property_as_string(wchar_t const *property_name,
                                            size_t default_buffer_size = 256) const {
            std::wstring b(default_buffer_size, 0);
            std::error_code status{try_get_property(property_name, &b)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return b;
        }

        template<typename T>
        T get_property_as(wchar_t const *property_name) const {
            T value{};
            std::error_code status{try_get_property<T>(property_name, &value)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return value;
        }

        template<typename T>
        size_t get_property(wchar_t const *property_name, T *value) const {
            size_t property_size{0};
            std::error_code status{try_get_property(property_name, &value, &property_size)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return property_size;
        }

        [[nodiscard]] std::error_code try_set_property(wchar_t const *property_name,
                                                       char const *buffer,
                                                       size_t buffer_size) {
            std::error_code status{hcrypt::nte_error_to_status(NCryptSetProperty(
                get_object_handle(),
                property_name,
                reinterpret_cast<unsigned char *>(const_cast<char *>(buffer)),
                static_cast<unsigned long>(buffer_size),
                0))};
            return status;
        }

        [[nodiscard]] std::error_code try_set_property(wchar_t const *property_name,
                                                       hcrypt::buffer const &buffer) {
            std::error_code status{
                try_set_property(property_name,
                                 const_cast<unsigned char *>(buffer.data()),
                                 static_cast<unsigned long>(buffer.size()))};
            return status;
        }

        [[nodiscard]] std::error_code try_set_property(wchar_t const *property_name,
                                                       std::wstring const &buffer) {
            std::error_code status{try_set_property(
                property_name,
                const_cast<unsigned char *>(buffer.data()),
                static_cast<unsigned long>(buffer.size() * sizeof(wchar_t)))};
            return status;
        }

        template<typename T>
        [[nodiscard]] std::error_code try_set_property(wchar_t const *property_name,
                                                       T const &value) {
            std::error_code status{try_set_property(property_name, &value, sizeof(value))};
            return status;
        }

        void set_property(wchar_t const *property_name, char const *buffer, size_t buffer_size) {
            std::error_code status{try_set_property(property_name, buffer, buffer_size)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptSetProperty failed");
            }
        }

        template<typename T>
        void set_property(wchar_t const *property_name, T const &value) {
            std::error_code status{try_set_property(property_name, value)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptSetProperty failed");
            }
        }

        NCRYPT_HANDLE get_object_handle() const {
            return static_cast<T const *>(this)->get_handle();
        }

    public:
        [[nodiscard]] std::error_code try_get_algorithm_name(std::wstring *name) const noexcept {
            return try_get_property(NCRYPT_ALGORITHM_GROUP_PROPERTY, name);
        }

        std::wstring get_algorithm_name() const {
            return get_property_as_string(NCRYPT_ALGORITHM_GROUP_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_associated_ecdh_name(std::wstring *name) const
            noexcept {
            return try_get_property(NCRYPT_ASSOCIATED_ECDH_KEY, name);
        }

        std::wstring get_associated_ecdh_name() const {
            std::wstring name;
            hcrypt::status status{try_get_property(NCRYPT_ASSOCIATED_ECDH_KEY, &name)};
            if (!hcrypt::is_success(status) && status != hcrypt::status::not_found) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return name;
        }

        [[nodiscard]] std::error_code try_get_block_length(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_BLOCK_LENGTH_PROPERTY, value);
        }

        unsigned long get_block_length() const {
            return get_property_as<unsigned long>(NCRYPT_BLOCK_LENGTH_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_certificate(hcrypt::buffer *b) const noexcept {
            return try_get_property(NCRYPT_CERTIFICATE_PROPERTY, b);
        }

        hcrypt::buffer get_certificate() const {
            return get_property_as_buffer(NCRYPT_CERTIFICATE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_dh_parameters(hcrypt::buffer *b) const noexcept {
            return try_get_property(NCRYPT_DH_PARAMETERS_PROPERTY, b);
        }

        [[nodiscard]] std::error_code try_set_dh_parameters(BCRYPT_DH_PARAMETER_HEADER const *b,
                                                            size_t length_in_bytes) noexcept {
            return try_set_property(NCRYPT_DH_PARAMETERS_PROPERTY,
                                    reinterpret_cast<char const *>(b),
                                    length_in_bytes);
        }

        hcrypt::buffer get_dh_parameters() const {
            return get_property_as_buffer(NCRYPT_DH_PARAMETERS_PROPERTY);
        }

        void set_dh_parameters(BCRYPT_DH_PARAMETER_HEADER const *b,
                               size_t length_in_bytes) noexcept {
            set_property(NCRYPT_DH_PARAMETERS_PROPERTY,
                         reinterpret_cast<char const *>(b),
                         length_in_bytes);
        }

        [[nodiscard]] std::error_code try_get_export_policy(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_EXPORT_POLICY_PROPERTY, value);
        }

        unsigned long get_export_policy() const {
            return get_property_as<unsigned long>(NCRYPT_EXPORT_POLICY_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_implementation_flags(unsigned long *value) const
            noexcept {
            return try_get_property(NCRYPT_IMPL_TYPE_PROPERTY, value);
        }

        unsigned long get_implementation_flags() const {
            return get_property_as<unsigned long>(NCRYPT_IMPL_TYPE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_key_type(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_KEY_TYPE_PROPERTY, value);
        }

        unsigned long get_key_type() const {
            return get_property_as<unsigned long>(NCRYPT_KEY_TYPE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_key_usage(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_KEY_USAGE_PROPERTY, value);
        }

        unsigned long get_key_usage() const {
            return get_property_as<unsigned long>(NCRYPT_KEY_USAGE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_last_modified(FILETIME *value) const noexcept {
            return try_get_property(NCRYPT_LAST_MODIFIED_PROPERTY, value);
        }

        FILETIME get_last_modified() const {
            return get_property_as<FILETIME>(NCRYPT_LAST_MODIFIED_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_length(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_LENGTH_PROPERTY, value);
        }

        unsigned long get_length() const {
            return get_property_as<unsigned long>(NCRYPT_LENGTH_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_supported_lengths(NCRYPT_SUPPORTED_LENGTHS *value) const
            noexcept {
            return try_get_property(NCRYPT_LENGTHS_PROPERTY, value);
        }

        NCRYPT_SUPPORTED_LENGTHS get_supported_lengths() const {
            return get_property_as<NCRYPT_SUPPORTED_LENGTHS>(NCRYPT_LENGTHS_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_max_name_length(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_MAX_NAME_LENGTH_PROPERTY, value);
        }

        unsigned long get_max_name_length() const {
            return get_property_as<unsigned long>(NCRYPT_MAX_NAME_LENGTH_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_name(std::wstring *name) const noexcept {
            return try_get_property(NCRYPT_NAME_PROPERTY, name);
        }

        std::wstring get_name() const {
            return get_property_as_string(NCRYPT_NAME_PROPERTY);
        }

        [[nodiscard]] std::error_code try_set_pin_property(std::wstring_view const &pin) {
            return try_set_property(NCRYPT_PIN_PROPERTY,
                                    reinterpret_cast<char const *>(pin.data()),
                                    pin.size());
        }

        void set_pin_property(std::wstring_view const &pin) {
            set_property(NCRYPT_PIN_PROPERTY,
                         reinterpret_cast<char const *>(pin.data()),
                         pin.size());
        }

        [[nodiscard]] std::error_code try_set_reader(std::wstring_view const &reader) {
            return try_set_property(NCRYPT_READER_PROPERTY,
                                    reinterpret_cast<char const *>(reader.data()),
                                    reader.size());
        }

        void set_reader(std::wstring_view const &reader) {
            set_property(NCRYPT_READER_PROPERTY,
                         reinterpret_cast<char const *>(reader.data()),
                         reader.size());
        }

        [[nodiscard]] std::error_code try_get_storage_provider(storage_provider *value) const
            noexcept;

        storage_provider get_storage_provider() const;

        [[nodiscard]] std::error_code try_get_pin_id(pin_id *pid) const noexcept {
            return try_get_property(NCRYPT_SCARD_PIN_ID, pid);
        }

        pin_id get_ping_id() const {
            return get_property_as<pin_id>(NCRYPT_SCARD_PIN_ID);
        }

        [[nodiscard]] std::error_code try_get_pin_info(PIN_INFO *pin_info) const noexcept {
            return try_get_property(NCRYPT_SCARD_PIN_INFO, pin_info);
        }

        PIN_INFO get_ping_info() const {
            return get_property_as<PIN_INFO>(NCRYPT_SCARD_PIN_INFO);
        }

        [[nodiscard]] std::error_code try_get_root_certificate_store(HCERTSTORE *value) const
            noexcept {
            return try_get_property(NCRYPT_ROOT_CERTSTORE_PROPERTY, value);
        }

        HCERTSTORE get_root_certificate_store() const {
            return get_property_as<>(NCRYPT_ROOT_CERTSTORE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_set_secure_pin(std::wstring_view const &secure_pin) {
            return try_set_property(NCRYPT_SECURE_PIN_PROPERTY,
                                    reinterpret_cast<char const *>(secure_pin.data()),
                                    secure_pin.size());
        }

        void set_secure_pin(std::wstring_view const &secure_pin) {
            set_property(NCRYPT_SECURE_PIN_PROPERTY,
                         reinterpret_cast<char const *>(secure_pin.data()),
                         secure_pin.size());
        }

        [[nodiscard]] std::error_code try_get_security_descriptor(hcrypt::buffer *b) const
            noexcept {
            return try_get_property(NCRYPT_SECURITY_DESCR_PROPERTY, b);
        }

        hcrypt::buffer get_security_descriptor() const {
            return get_property_as_buffer(NCRYPT_SECURITY_DESCR_PROPERTY);
        }

        [[nodiscard]] std::error_code try_set_security_descriptor(char const *sd, size_t sd_size) {
            return try_set_property(NCRYPT_SECURITY_DESCR_PROPERTY,
                                    reinterpret_cast<char const *>(sd),
                                    sd_size);
        }

        void set_security_descriptor(char const *sd, size_t sd_size) {
            set_property(NCRYPT_SECURITY_DESCR_PROPERTY,
                         reinterpret_cast<char const *>(sd),
                         sd_size);
        }

        [[nodiscard]] std::error_code try_get_security_descriptor_supported(unsigned long *value) const
            noexcept {
            return try_get_property(NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, value);
        }

        bool get_security_descriptor_supported() const {
            unsigned long value{0};
            hcrypt::status status{try_get_property(
                NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, &value)};
            if (!hcrypt::is_success(status) && status != hcrypt::status::not_found) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return hcrypt::is_flag_on(value, 1);
        }

        [[nodiscard]] std::error_code try_get_smartcard_guid(GUID *value) const noexcept {
            return try_get_property(NCRYPT_SMARTCARD_GUID_PROPERTY, value);
        }

        GUID get_smartcard_guid() const {
            return get_property_as<GUID>(NCRYPT_SMARTCARD_GUID_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_ui_policy(hcrypt::buffer *b) const noexcept {
            return try_get_property(NCRYPT_UI_POLICY_PROPERTY, b);
        }

        [[nodiscard]] std::error_code try_set_ui_policy(NCRYPT_UI_POLICY const *b,
                                                        size_t length_in_bytes) noexcept {
            return try_set_property(NCRYPT_UI_POLICY_PROPERTY,
                                    reinterpret_cast<char const *>(b),
                                    length_in_bytes);
        }

        hcrypt::buffer get_ui_policy() const {
            return get_property_as_buffer(NCRYPT_UI_POLICY_PROPERTY);
        }

        void set_ui_policy(NCRYPT_UI_POLICY const *b, size_t length_in_bytes) noexcept {
            set_property(NCRYPT_UI_POLICY_PROPERTY, reinterpret_cast<char const *>(b), length_in_bytes);
        }

        [[nodiscard]] std::error_code try_get_uniqie_name(std::wstring *name) const noexcept {
            return try_get_property(NCRYPT_UNIQUE_NAME_PROPERTY, name);
        }

        std::wstring get_unique_name() const {
            return get_property_as_string(NCRYPT_UNIQUE_NAME_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_use_context(std::wstring *name) const noexcept {
            return try_get_property(NCRYPT_USE_CONTEXT_PROPERTY, name);
        }

        std::wstring get_use_context() const {
            return get_property_as_string(NCRYPT_USE_CONTEXT_PROPERTY);
        }

        [[nodiscard]] std::error_code try_set_use_context(std::wstring_view const &use_context) {
            return try_set_property(NCRYPT_USE_CONTEXT_PROPERTY,
                                    reinterpret_cast<char const *>(use_context.data()),
                                    use_context.size());
        }

        void set_use_context(std::wstring_view const &use_context) {
            set_property(NCRYPT_USE_CONTEXT_PROPERTY,
                         reinterpret_cast<char const *>(use_context.data()),
                         use_context.size());
        }

        [[nodiscard]] std::error_code try_get_use_count_enabled(unsigned long *value) const
            noexcept {
            return try_get_property(NCRYPT_USE_COUNT_ENABLED_PROPERTY, value);
        }

        bool get_use_count_enabled() const {
            unsigned long value{0};
            hcrypt::status status{try_get_property(NCRYPT_USE_COUNT_ENABLED_PROPERTY, &value)};
            if (!hcrypt::is_success(status) && status != hcrypt::status::not_found) {
                throw std::system_error(status, "NCryptGetProperty failed");
            }
            return hcrypt::is_flag_on(value, 1);
        }

        [[nodiscard]] std::error_code try_get_use_count(unsigned long long *value) const noexcept {
            return try_get_property(NCRYPT_USE_COUNT_PROPERTY, value);
        }

        unsigned long long get_use_count() const {
            return get_property_as<unsigned long long>(NCRYPT_USE_COUNT_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_user_certificate_store(HCERTSTORE *value) const
            noexcept {
            return try_get_property(NCRYPT_USER_CERTSTORE_PROPERTY, value);
        }

        HCERTSTORE get_user_certificate_store() const {
            return get_property_as<>(NCRYPT_USER_CERTSTORE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_version(unsigned long *value) const noexcept {
            return try_get_property(NCRYPT_VERSION_PROPERTY, value);
        }

        unsigned long get_version() const {
            return get_property_as<unsigned long>(NCRYPT_VERSION_PROPERTY);
        }

        [[nodiscard]] std::error_code try_get_hwnd(HWND *value) const noexcept {
            return try_get_property(NCRYPT_WINDOW_HANDLE_PROPERTY, value);
        }

        HWND get_hwnd() const {
            return get_property_as<HWND>(NCRYPT_WINDOW_HANDLE_PROPERTY);
        }

        [[nodiscard]] std::error_code try_set_hwnd(HWND value) const noexcept {
            return try_set_property(NCRYPT_WINDOW_HANDLE_PROPERTY, value);
        }

        void get_hwnd(HWND value) const {
            return set_property(NCRYPT_WINDOW_HANDLE_PROPERTY, value);
        }
    };

    inline bool is_key_handle(NCRYPT_KEY_HANDLE k) {
        return NCryptIsKeyHandle(k) ? true : false;
    }

    class key final: public property_impl<key> {
    public:
        friend class storage_provider;

        using handle_t = NCRYPT_KEY_HANDLE;

        key() noexcept = default;

        explicit key(NCRYPT_KEY_HANDLE h) noexcept
            : h_(h) {
        }

        key(key const &) = delete;
        key &operator=(key const &) = delete;

        key(key &&other) noexcept
            : h_(other.detach()) {
        }

        key &operator=(key &&other) noexcept {
            if (this != &other) {
                close();
                h_ = other.detach();
            }
            return *this;
        }

        ~key() noexcept {
            close();
        }

        NCRYPT_KEY_HANDLE get_handle() const {
            return h_;
        }

        [[nodiscard]] NCRYPT_KEY_HANDLE detach() noexcept {
            NCRYPT_KEY_HANDLE h{h_};
            h_ = 0;
            return h;
        }

        void attach(NCRYPT_KEY_HANDLE h) noexcept {
            close();
            h_ = h;
        }

        void swap(key &other) noexcept {
            NCRYPT_KEY_HANDLE h{h_};
            h_ = other.h_;
            other.h_ = h;
        }

        bool is_valid() const noexcept {
            return h_ != 0;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        void close() noexcept {
            if (is_valid()) {
                std::error_code status{static_cast<hcrypt::status>(NCryptFreeObject(h_))};
                BCRYPT_CODDING_ERROR_IF_NOT(hcrypt::is_success(status));
                h_ = 0;
            }
        }

    private:
        NCRYPT_KEY_HANDLE h_{0};
    };

    inline void swap(key &l, key &r) noexcept {
        l.swap(r);
    }

    class storage_provider final: public property_impl<storage_provider> {
    public:
        using handle_t = NCRYPT_PROV_HANDLE;

        //
        // Workaround for clang bogus warning
        // https://stackoverflow.com/questions/43819314/default-member-initializer-needed-within-definition-of-enclosing-class-outside
        //
        storage_provider() noexcept {
        } //= default;

        explicit storage_provider(wchar_t const *provider) {
            open(provider);
        }

        explicit storage_provider(NCRYPT_PROV_HANDLE h) noexcept
            : h_(h) {
        }

        storage_provider(storage_provider const &) = delete;
        storage_provider &operator=(storage_provider const &) = delete;

        storage_provider(storage_provider &&other) noexcept
            : h_(other.detach()) {
        }

        storage_provider &operator=(storage_provider &&other) noexcept {
            if (this != &other) {
                close();
                h_ = other.detach();
            }
            return *this;
        }

        ~storage_provider() noexcept {
            close();
        }

        NCRYPT_PROV_HANDLE get_handle() const {
            return h_;
        }

        [[nodiscard]] NCRYPT_PROV_HANDLE detach() noexcept {
            NCRYPT_PROV_HANDLE h{h_};
            h_ = 0;
            return h;
        }

        void attach(NCRYPT_PROV_HANDLE h) noexcept {
            close();
            h_ = h;
        }

        void swap(storage_provider &other) noexcept {
            NCRYPT_PROV_HANDLE h{h_};
            h_ = other.h_;
            other.h_ = h;
        }

        bool is_valid() const noexcept {
            return h_ != 0;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        [[nodiscard]] std::error_code try_open(wchar_t const *provider) noexcept {
            close();
            std::error_code status{hcrypt::nte_error_to_status(
                NCryptOpenStorageProvider(&h_, provider, 0))};
            return status;
        }

        void open(wchar_t const *provider) {
            std::error_code status{try_open(provider)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptOpenStorageProvider failed");
            }
        }

        void close() noexcept {
            if (is_valid()) {
                std::error_code status{static_cast<hcrypt::status>(NCryptFreeObject(h_))};
                BCRYPT_CODDING_ERROR_IF_NOT(hcrypt::is_success(status));
                h_ = 0;
            }
        }

        [[nodiscard]] inline std::error_code try_enum_algorithms(
            algorithm_name_t *algorithms,
            unsigned long algorithm_operations,
            unsigned long flags = NCRYPT_SILENT_FLAG) noexcept {
            NCryptAlgorithmName *algorithms_buffer{nullptr};
            unsigned long algorithms_count{0};
            hcrypt::status err{hcrypt::nte_error_to_status(NCryptEnumAlgorithms(
                h_, algorithm_operations, &algorithms_count, &algorithms_buffer, flags))};

            if (hcrypt::is_success(err)) {
                algorithms->first.attach(algorithms_buffer);
                algorithms->second = algorithms_count;
            }
            return err;
        }

        inline algorithm_name_t const enum_algorithm(unsigned long algorithm_operations,
                                                     unsigned long flags = NCRYPT_SILENT_FLAG) {
            algorithm_name_t algorithms;
            std::error_code err{try_enum_algorithms(&algorithms, algorithm_operations, flags)};
            if (hcrypt::is_failure(err)) {
                throw std::system_error(err, "NCryptEnumAlgorithms failed");
            }
            return algorithms;
        }

        class key_iterator final {
            friend class storage_provider;

            key_iterator(storage_provider *p, unsigned long flags)
                : p_{p}
                , flags_{flags} {
                advance();
            }

        public:
            using iterator_category = std::forward_iterator_tag;
            using value_type = NCryptKeyName;
            using pointer = NCryptKeyName *;
            using reference = NCryptKeyName &;

            key_iterator(key_iterator const &) = delete;
            key_iterator &operator=(key_iterator const &) = delete;

            key_iterator() {
            }

            key_iterator(key_iterator &&other)
                : p_{other.p_}
                , enumirator_state_{other.enumirator_state_}
                , flags_{other.flags_}
                , k_{std::move(other.k_)} {
                other.k_ = nullptr;
                other.enumirator_state_ = nullptr;
                other.flags_ = 0;
            }

            key_iterator &operator=(key_iterator &&other) {
                if (this != &other) {
                    k_ = std::move(other.k_);
                    p_ = other.p_;
                    enumirator_state_ = other.enumirator_state_;
                    flags_ = other.flags_;
                    other.k_ = nullptr;
                    other.enumirator_state_ = nullptr;
                    other.flags_ = 0;
                }
                return *this;
            }

            ~key_iterator() {
                close();
            }

            void swap(key_iterator &other) noexcept {
                storage_provider *p{other.p_};
                key_name_cptr k{std::move(other.k_)};
                void *enumirator_state{other.enumirator_state_};
                unsigned long flags = other.flags_;

                other.p_ = p_;
                other.k_ = std::move(k_);
                other.enumirator_state_ = enumirator_state_;
                other.flags_ = flags_;

                p_ = p;
                k_ = std::move(k);
                enumirator_state_ = enumirator_state;
                flags_ = flags;
            }

            explicit operator bool() const noexcept {
                return enumirator_state_ ? true : false;
            }

            bool operator==(key_iterator const &other) const noexcept {
                return !enumirator_state_ && !other.enumirator_state_;
            }

            bool operator!=(key_iterator const &other) const noexcept {
                return !operator==(other);
            }

            key_iterator &operator++() noexcept {
                advance();
                return *this;
            }

            NCryptKeyName const &operator*() const noexcept {
                return *k_;
            }

            NCryptKeyName const *operator->() const noexcept {
                return k_.get();
            }

        private:
            void close() {
                if (enumirator_state_) {
                    std::error_code status{static_cast<hcrypt::status>(
                        NCryptFreeBuffer(enumirator_state_))};
                    BCRYPT_CODDING_ERROR_IF_NOT(hcrypt::is_success(status));
                    enumirator_state_ = nullptr;
                }
                p_ = nullptr;
                k_.free();
                flags_ = 0;
            }

            void advance() {
                NCryptKeyName *key_name{nullptr};
                SECURITY_STATUS status{NCryptEnumKeys(
                    p_->get_handle(), nullptr, &key_name, &enumirator_state_, flags_)};

                if (NTE_NO_MORE_ITEMS == status) {
                    close();
                } else if (ERROR_SUCCESS == status) {
                    k_.attach(key_name);
                } else {
                    throw std::system_error(hcrypt::nte_error_to_status(status),
                                            "NCryptEnumKeys failed");
                }
            }

            storage_provider *p_{nullptr};
            void *enumirator_state_{nullptr};
            unsigned long flags_;
            key_name_cptr k_;
        };

        key_iterator key_begin(unsigned long flags) {
            return key_iterator{this, flags};
        }

        key_iterator key_end() {
            return key_iterator{};
        }

        std::error_code try_is_algorithm_supported(wchar_t const *algorithm_id,
                                                   unsigned long flags) {
            std::error_code status{hcrypt::nte_error_to_status(
                NCryptIsAlgSupported(h_, algorithm_id, flags))};
            return status;
        }

        bool is_algorithm_supported(wchar_t const *algorithm_id, unsigned long flags) {
            bool result{false};
            std::error_code status{try_is_algorithm_supported(algorithm_id, flags)};
            if (status == hcrypt::status::success) {
                result = true;
            } else if (status != hcrypt::status::not_supported) {
                throw std::system_error(status, "NCryptIsAlgSupported failed");
            }
            return result;
        }

        std::error_code try_open_key(wchar_t const *key_name,
                                     unsigned long legacy_key_spec,
                                     unsigned long flags,
                                     key *k) {
            NCRYPT_KEY_HANDLE new_key{0};
            std::error_code status{hcrypt::nte_error_to_status(
                NCryptOpenKey(h_, &new_key, key_name, legacy_key_spec, flags))};

            if (hcrypt::is_failure(status)) {
                return status;
            }
            k->attach(new_key);
            return status;
        }

        key open_key(wchar_t const *key_name, unsigned long legacy_key_spec, unsigned long flags) {
            key new_key;
            std::error_code status{try_open_key(key_name, legacy_key_spec, flags, &new_key)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptOpenKey failed");
            }
            return new_key;
        }

        std::error_code try_create_key(wchar_t const *algorithm_id,
                                       wchar_t const *key_name,
                                       unsigned long legacy_key_spec,
                                       unsigned long flags,
                                       key *k) {
            NCRYPT_KEY_HANDLE new_key{0};
            std::error_code status{hcrypt::nte_error_to_status(NCryptCreatePersistedKey(
                h_, &new_key, algorithm_id, key_name, legacy_key_spec, flags))};

            if (hcrypt::is_failure(status)) {
                return status;
            }
            k->attach(new_key);
            return status;
        }

        key create_key(wchar_t const *algorithm_id,
                       wchar_t const *key_name,
                       unsigned long legacy_key_spec,
                       unsigned long flags) {
            key new_key;
            std::error_code status{try_create_key(
                algorithm_id, key_name, legacy_key_spec, flags, &new_key)};
            if (hcrypt::is_failure(status)) {
                throw std::system_error(status, "NCryptCreatePersistedKey failed");
            }
            return new_key;
        }

        // try_import_key NCryptImportKey

        // notify_changes NCryptNotifyChangeKey

    private:
        NCRYPT_PROV_HANDLE h_{0};
    };

    inline void swap(storage_provider &l, storage_provider &r) noexcept {
        l.swap(r);
    }

    inline void swap(storage_provider::key_iterator &l,
                     storage_provider::key_iterator &r) noexcept {
        l.swap(r);
    }

    template<typename T>
    [[nodiscard]] std::error_code property_impl<T>::try_get_storage_provider(storage_provider *value) const
        noexcept {
        NCRYPT_PROV_HANDLE h{0};
        std::error_code error{try_get_property(NCRYPT_PROVIDER_HANDLE_PROPERTY, &h)};
        if (hcrypt::is_success(error)) {
            value->attach(h);
        }
        return error;
    }

    template<typename T>
    storage_provider property_impl<T>::get_storage_provider() const {
        return storage_provider{
            get_property_as<NCRYPT_PROV_HANDLE>(NCRYPT_PROVIDER_HANDLE_PROPERTY)};
    }

} // namespace ncrypt