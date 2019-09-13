#pragma once

#include "hcrypt_common.h"
#include <bcrypt.h>

#pragma comment (lib, "bcrypt.lib")

namespace bcrypt {

    template<typename T = void>
    class buffer_ptr {
    public:

        using value_type = T;
        using mutable_value_type = std::remove_const_t<T>;
        constexpr static bool is_void{ std::is_void_v<std::remove_cv_t<T>> };
        using reference_type = std::conditional_t<
                                        is_void,
                                        void, 
                                        std::add_lvalue_reference_t<T>>;
        using pointer_type = T*;
        using mutable_pointer_type = mutable_value_type*;

        buffer_ptr() noexcept = default;

        buffer_ptr(pointer_type p) noexcept
            : p_(p) {
        }

        buffer_ptr(buffer_ptr const &) noexcept = delete;
        buffer_ptr &operator= (buffer_ptr const&) noexcept = delete;

        buffer_ptr(buffer_ptr&& other) noexcept
            : p_{other.detach()} {
        }

        buffer_ptr &operator= (buffer_ptr&& other) noexcept {
            if (this != &other) {
                free();
                p_ = other.detach();
            }
            return *this;
        }

        ~buffer_ptr() noexcept {
            free();
        }

        void swap(buffer_ptr& other) noexcept {
            pointer_type p{ p_ };
            p_ = other.p_;
            other.p_ = p;
        }

        pointer_type get() const noexcept {
            return p_;
        }

        reference_type operator * () const noexcept {
            return *p_; 
        }

        pointer_type operator -> () const noexcept {
            return p_; 
        }

        void free() noexcept {
            if (p_) {
                BCryptFreeBuffer(const_cast<mutable_pointer_type>(p_));
                p_ = nullptr;
            }
        }

        pointer_type detach() noexcept {
            pointer_type p{ p_ };
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
        pointer_type p_{ nullptr };
    };

    template < typename T>
    inline void swap(buffer_ptr<T> first, buffer_ptr<T> second)  noexcept {
        first.swap(second);
    }

    using providers_cptr = buffer_ptr<CRYPT_PROVIDERS const>;

    [[nodiscard]]
    inline NTSTATUS try_enum_registered_providers(providers_cptr *providers) noexcept {
        CRYPT_PROVIDERS* buffer{ nullptr };
        unsigned long element_count{ 0 };
        NTSTATUS status{ BCryptEnumRegisteredProviders(&element_count, &buffer) };
        if (NT_SUCCESS(status)) {
            providers->attach(buffer);
        }
        return status;
    }

    inline providers_cptr const enum_registered_providers() {
        providers_cptr providers;
        NTSTATUS status{ try_enum_registered_providers(&providers) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEnumRegisteredProviders failed");
        }
        return providers;
    }

    template<typename FN>
    inline void find_first(providers_cptr const& providers, FN const& fn) {
        if (providers) {
            for (unsigned long idx = 0; idx < providers->cProviders; ++idx) {
                if (!fn(providers->rgpszProviders[idx])) {
                    break;
                }
            }
        }
    }

    using provider_registration_cptr = buffer_ptr<CRYPT_PROVIDER_REG const>;

    [[nodiscard]]
    inline NTSTATUS try_query_provider_registartion(LPCWSTR provider,
                                                    unsigned long mode,
                                                    unsigned long itf_id,
                                                    provider_registration_cptr *registartion) noexcept {

        CRYPT_PROVIDER_REG* registration_buffer{ nullptr };
        unsigned long buffer_size{ 0 };
        NTSTATUS status{ BCryptQueryProviderRegistration(provider, 
                                                         mode, 
                                                         itf_id,
                                                         &buffer_size,
                                                         &registration_buffer) };
        if (NT_SUCCESS(status)) {
            if (buffer_size) {
                registartion->attach(registration_buffer);
            } else {
                registartion->free();
            }
        }
        return status;
    }

    inline provider_registration_cptr const query_provider_registartion(LPCWSTR provider,
                                                                        unsigned long mode,
                                                                        unsigned long itf_id) {
        provider_registration_cptr registartion;
        NTSTATUS status{ try_query_provider_registartion(provider,
                                                         mode,
                                                         itf_id,
                                                         &registartion) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptQueryProviderRegistration failed");
        }
        return registartion;
    }

        
    using provider_registration_refs_cptr = buffer_ptr<CRYPT_PROVIDER_REFS const>;

    [[nodiscard]]
    inline NTSTATUS try_resolve_providers(wchar_t const *context,
                                          unsigned long itf_id,
                                          wchar_t const *function,
                                          wchar_t const *provider,
                                          unsigned long mode,
                                          unsigned long flags,
                                          provider_registration_refs_cptr *registration) noexcept {
        CRYPT_PROVIDER_REFS* registration_buffer{ nullptr };
        unsigned long buffer_size{ 0 };
        NTSTATUS status{ BCryptResolveProviders(context,
                                                itf_id,
                                                function,
                                                provider,
                                                mode,
                                                flags,
                                                &buffer_size,
                                                &registration_buffer) };
        if (NT_SUCCESS(status)) {
            if (buffer_size) {
                registration->attach(registration_buffer);
            } else {
                registration->free();
            }
        }
        return status;
    }

    inline provider_registration_refs_cptr const resolve_providers( wchar_t const *context,
                                                                    unsigned long itf_id,
                                                                    wchar_t const *function,
                                                                    wchar_t const *provider,
                                                                    unsigned long mode,
                                                                    unsigned long flags) {
        provider_registration_refs_cptr registartion;
        NTSTATUS status{ try_resolve_providers(context,
                                               itf_id,
                                               function,
                                               provider,
                                               mode,
                                               flags,
                                               &registartion) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptResolveProviders failed");
        }
        return registartion;
    }

    template<typename FN>
    inline void find_first(provider_registration_refs_cptr const& registration, FN const& fn) {
        if (registration) {
            for (unsigned long idx = 0; idx < registration->cProviders; ++idx) {
                if (!fn(registration->rgpProviders[idx])) {
                    break;
                }
            }
        }
    }

    using algorithm_identifiers_cptr = buffer_ptr<BCRYPT_ALGORITHM_IDENTIFIER const>;
    using algorithm_identifiers_t = std::pair<algorithm_identifiers_cptr, unsigned long>;

    [[nodiscard]]
    inline NTSTATUS try_enum_algorithms(unsigned long operations,
                                        algorithm_identifiers_t *algorithms) noexcept {
        BCRYPT_ALGORITHM_IDENTIFIER* algorithms_buffer{ nullptr };
        unsigned long algorithms_element_count{ 0 };
        NTSTATUS status{ BCryptEnumAlgorithms(operations,
                                                &algorithms_element_count,
                                                &algorithms_buffer,
                                                0) };
        if (NT_SUCCESS(status)) {
            algorithms->first.attach(algorithms_buffer);
            algorithms->second = algorithms_element_count;
        }
        return status;
    }

    inline algorithm_identifiers_t const enum_algorithms(unsigned long operations) {
        algorithm_identifiers_t algorithms;
        NTSTATUS status{ try_enum_algorithms(operations,
                                             &algorithms) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEnumAlgorithms failed");
        }
        return algorithms;
    }

    template<typename FN>
    inline void find_first(algorithm_identifiers_t const& providers, FN const& fn) {
        auto const& [buffer, element_count] = providers;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            if (!fn(buffer.get()[idx])) {
                break;
            }
        }
    }

    using crypto_context_cptr = buffer_ptr<CRYPT_CONTEXTS const>;

    [[nodiscard]]
    inline NTSTATUS try_enum_crypto_context(unsigned long table,
                                            crypto_context_cptr *crypto_contexts) noexcept {
        CRYPT_CONTEXTS* buffer{ nullptr };
        unsigned long buffer_size{ 0 };
        NTSTATUS status{ BCryptEnumContexts(table , &buffer_size, &buffer) };
        if (NT_SUCCESS(status)) {
            crypto_contexts->attach(buffer);
        }
        return status;
    }

    inline crypto_context_cptr const enum_crypto_context(unsigned long table) {
        crypto_context_cptr crypto_contexts;
        NTSTATUS status{ try_enum_crypto_context(table,
                                                 &crypto_contexts) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEnumContexts failed");
        }
        return crypto_contexts;
    }

    template<typename FN>
    inline void find_first(crypto_context_cptr const& crypto_contexts, FN const& fn) {
        if (crypto_contexts) {
            for (unsigned long idx = 0; idx < crypto_contexts->cContexts; ++idx) {
                if (!fn(crypto_contexts->rgpszContexts[idx])) {
                    break;
                }
            }
        }
    }

    using crypto_context_function_cptr = buffer_ptr<CRYPT_CONTEXT_FUNCTIONS const>;

    [[nodiscard]]
    inline NTSTATUS try_enum_crypto_context_function(unsigned long table,
                                                     wchar_t const *crypto_context,
                                                     unsigned long itf_id,
                                                     crypto_context_function_cptr * crypto_context_functions) noexcept {
        CRYPT_CONTEXT_FUNCTIONS* buffer{ nullptr };
        unsigned long buffer_size{ 0 };
        NTSTATUS status{ BCryptEnumContextFunctions(table , 
                                                    crypto_context , 
                                                    itf_id, 
                                            &buffer_size, &buffer) };
        if (NT_SUCCESS(status)) {
            crypto_context_functions->attach(buffer);
        }
        return status;
    }

    inline crypto_context_function_cptr const enum_crypto_context_function(unsigned long table,
                                                                           wchar_t const* crypto_context,
        unsigned long itf_id) {
        crypto_context_function_cptr crypto_context_functions;
        NTSTATUS status{ try_enum_crypto_context_function(table,
                                                          crypto_context,
                                                          itf_id,
                                                          &crypto_context_functions) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEnumContextFunctions failed");
        }
        return crypto_context_functions;
    }

    template<typename FN>
    inline void find_first(crypto_context_function_cptr const& crypto_context_functions, FN const& fn) {
        if (crypto_context_functions) {
            for (unsigned long idx = 0; idx < crypto_context_functions->cFunctions; ++idx) {
                if (!fn(crypto_context_functions->rgpszFunctions[idx])) {
                    break;
                }
            }
        }
    }

    using crypto_context_function_providers_cptr = buffer_ptr<CRYPT_CONTEXT_FUNCTION_PROVIDERS  const>;

    [[nodiscard]]
    inline NTSTATUS try_enum_crypto_context_function_providers(unsigned long table,
                                                               wchar_t const *crypto_context,
                                                               unsigned long itf_id,
                                                               wchar_t const *function,
                                                               crypto_context_function_providers_cptr * crypto_context_function_providers) noexcept {
        CRYPT_CONTEXT_FUNCTION_PROVIDERS* buffer{ nullptr };
        unsigned long buffer_size{ 0 };
        NTSTATUS status{ BCryptEnumContextFunctionProviders(table ,
                                                            crypto_context, 
                                                            itf_id, 
                                                            function,
                                                            &buffer_size, 
                                                            &buffer) };
        if (NT_SUCCESS(status)) {
            crypto_context_function_providers->attach(buffer);
        }
        return status;
    }

    inline crypto_context_function_providers_cptr const enum_crypto_context_function_providers(unsigned long table,
                                                                                               wchar_t const* crypto_context,
                                                                                               unsigned long itf_id,
                                                                                               wchar_t const* function) {
        crypto_context_function_providers_cptr crypto_context_function_providers;
        NTSTATUS status{ try_enum_crypto_context_function_providers(table,
                                                                    crypto_context,
                                                                    itf_id,
                                                                    function,
                                                                    &crypto_context_function_providers) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEnumContextFunctionProviders failed");
        }
        return crypto_context_function_providers;
    }

    template<typename FN>
    inline void find_first(crypto_context_function_providers_cptr const& crypto_context_function_providers, FN const& fn) {
        if (crypto_context_function_providers) {
            for (unsigned long idx = 0; idx < crypto_context_function_providers->cProviders; ++idx) {
                if (!fn(crypto_context_function_providers->rgpszProviders[idx])) {
                    break;
                }
            }
        }
    }

    [[nodiscard]]
    inline NTSTATUS try_is_fips_complience_on(bool* complience_on) noexcept {
        BOOLEAN flag{ false };
        NTSTATUS status = BCryptGetFipsAlgorithmMode(&flag);
        *complience_on = flag ? true : false;
        return status;
    }

    [[nodiscard]]
    inline bool is_fips_complience_on() {
        bool complience_on{ false };
        NTSTATUS status = try_is_fips_complience_on(&complience_on);
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGetFipsAlgorithmMode failed");
        }
        return complience_on;
    }

    constexpr inline wchar_t const* interface_id_to_string(unsigned long itf_id) {
        wchar_t const* itf_name{ L"unknown itf id" };
        switch (itf_id) {
        case BCRYPT_CIPHER_INTERFACE:
            itf_name = L"BCRYPT_CIPHER_INTERFACE";
            break;
        case BCRYPT_HASH_INTERFACE:
            itf_name = L"BCRYPT_HASH_INTERFACE";
            break;
        case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE:
            itf_name = L"BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE";
            break;
        case BCRYPT_SECRET_AGREEMENT_INTERFACE:
            itf_name = L"BCRYPT_SECRET_AGREEMENT_INTERFACE";
            break;
        case BCRYPT_SIGNATURE_INTERFACE:
            itf_name = L"BCRYPT_SIGNATURE_INTERFACE";
            break;
        case BCRYPT_RNG_INTERFACE:
            itf_name = L"BCRYPT_RNG_INTERFACE";
            break;
        case BCRYPT_KEY_DERIVATION_INTERFACE:
            itf_name = L"BCRYPT_KEY_DERIVATION_INTERFACE";
            break;
        case NCRYPT_KEY_STORAGE_INTERFACE:
            itf_name = L"NCRYPT_KEY_STORAGE_INTERFACE";
            break;
        case NCRYPT_SCHANNEL_INTERFACE:
            itf_name = L"NCRYPT_SCHANNEL_INTERFACE";
            break;
        case NCRYPT_SCHANNEL_SIGNATURE_INTERFACE:
            itf_name = L"NCRYPT_SCHANNEL_SIGNATURE_INTERFACE";
            break;
        case NCRYPT_KEY_PROTECTION_INTERFACE:
            itf_name = L"NCRYPT_KEY_PROTECTION_INTERFACE";
            break;
        }
        return itf_name;
    }

    constexpr inline wchar_t const* provider_mode_to_string(unsigned long mode) {
        wchar_t const* str{ L"unknown itf mode" };
        switch (mode) {
        case CRYPT_ANY:
            str = L"CRYPT_ANY";
            break;
        case CRYPT_UM:
            str = L"CRYPT_UM";
            break;
        case CRYPT_KM:
            str = L"CRYPT_KM";
            break;
        case CRYPT_MM:
            str = L"CRYPT_MM";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const* table_to_string(unsigned long table) {
        wchar_t const* str{ L"unknown table" };
        switch (table) {
        case CRYPT_DOMAIN:
            str = L"CRYPT_DOMAIN";
            break;
        case CRYPT_LOCAL:
            str = L"CRYPT_LOCAL";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const* dsa_algorithm_to_string(HASHALGORITHM_ENUM vals) {
        wchar_t const* str{ L"unknown algorithm" };
        switch (vals) {
        case DSA_HASH_ALGORITHM_SHA1:
            str = L"DSA_HASH_ALGORITHM_SHA1";
            break;
        case DSA_HASH_ALGORITHM_SHA256:
            str = L"DSA_HASH_ALGORITHM_SHA256";
            break;
        case DSA_HASH_ALGORITHM_SHA512:
            str = L"DSA_HASH_ALGORITHM_SHA512";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const* dsa_fips_version_to_string(DSAFIPSVERSION_ENUM vals) {
        wchar_t const* str{ L"unknown FIPS version" };
        switch (vals) {
        case DSA_FIPS186_2:
            str = L"DSA_FIPS186_2";
            break;
        case DSA_FIPS186_3:
            str = L"DSA_FIPS186_3";
            break;
        }
        return str;
    }

    inline std::wstring interface_flags_to_string(unsigned long flags) {
        std::wstring str;
        if ((flags & CRYPT_DOMAIN) == CRYPT_DOMAIN) {
            str += L"CRYPT_DOMAIN";
            //flags &= ~CRYPT_DOMAIN;
        }
        if ((flags & CRYPT_LOCAL) == CRYPT_LOCAL) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"CRYPT_LOCAL";
            //flags &= ~CRYPT_LOCAL;
        }
        return str;
    }

    inline std::wstring image_flags_to_string(unsigned long flags) {
        std::wstring str;
        if ((flags & static_cast<unsigned long>(CRYPT_MIN_DEPENDENCIES)) == static_cast<unsigned long>(CRYPT_MIN_DEPENDENCIES)) {
            str += L"CRYPT_MIN_DEPENDENCIES";
            //flags &= ~CRYPT_DOMAIN;
        }
        if ((flags & static_cast<unsigned long>(CRYPT_PROCESS_ISOLATE)) == static_cast<unsigned long>(CRYPT_PROCESS_ISOLATE)) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"CRYPT_PROCESS_ISOLATE";
            //flags &= ~CRYPT_LOCAL;
        }
        return str;
    }

    constexpr inline unsigned long const  interfaces[] = {
        BCRYPT_CIPHER_INTERFACE,
        BCRYPT_HASH_INTERFACE,
        BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE,
        BCRYPT_SECRET_AGREEMENT_INTERFACE,
        BCRYPT_SIGNATURE_INTERFACE,
        BCRYPT_RNG_INTERFACE,
        BCRYPT_KEY_DERIVATION_INTERFACE,
        NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_SCHANNEL_INTERFACE,
        NCRYPT_SCHANNEL_SIGNATURE_INTERFACE,
        NCRYPT_KEY_PROTECTION_INTERFACE,
    };

    template <typename F>
    constexpr inline void find_first_interface(F const &fn) {
        for (unsigned long itf_id : interfaces) {
            if (!fn(itf_id)) {
                break;
            }
        }
    }

    inline std::wstring algorithm_operations_to_string(unsigned long operations) {
        std::wstring str;
        if ((operations & (unsigned long)BCRYPT_CIPHER_OPERATION) == (unsigned long)BCRYPT_CIPHER_OPERATION) {
            str += L"BCRYPT_CIPHER_OPERATION";
            //flags &= ~BCRYPT_CIPHER_OPERATION;
        }
        if ((operations & (unsigned long)BCRYPT_HASH_OPERATION) == (unsigned long)BCRYPT_HASH_OPERATION) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"BCRYPT_HASH_OPERATION";
            //flags &= ~BCRYPT_HASH_OPERATION;
        }
        if ((operations & (unsigned long)BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION) == (unsigned long)BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION";
            //flags &= ~BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
        }
        if ((operations & (unsigned long)BCRYPT_SECRET_AGREEMENT_OPERATION) == (unsigned long)BCRYPT_SECRET_AGREEMENT_OPERATION) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"BCRYPT_SECRET_AGREEMENT_OPERATION";
            //flags &= ~BCRYPT_SECRET_AGREEMENT_OPERATION;
        }
        if ((operations & (unsigned long)BCRYPT_SIGNATURE_OPERATION) == (unsigned long)BCRYPT_SIGNATURE_OPERATION) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"BCRYPT_SIGNATURE_OPERATION";
            //flags &= ~BCRYPT_SIGNATURE_OPERATION;
        }
        if ((operations & (unsigned long)BCRYPT_RNG_OPERATION) == (unsigned long)BCRYPT_RNG_OPERATION) {
            if (!str.empty()) {
                str += L" | ";
            }
            str += L"BCRYPT_RNG_OPERATION";
            //flags &= ~BCRYPT_RNG_OPERATION;
        }
        return str;
    }

    template<typename FN>
    inline void find_first(BCRYPT_OID_LIST const *oid_list, FN const& fn) {
        if (oid_list) {
            for (unsigned long idx = 0; idx < oid_list->dwOIDCount; ++idx) {
                if (!fn(oid_list->pOIDs[idx])) {
                    break;
                }
            }
        }
    }

    enum class use_entropy_in_buffer {
        no = 0,
        yes = 0,
    };

    [[nodiscard]]
    inline NTSTATUS try_generate_random(char* buffer,
                                        size_t buffer_size,
                                        use_entropy_in_buffer use_buffer = use_entropy_in_buffer::no) noexcept {
        NTSTATUS status{ BCryptGenRandom(nullptr,
                                         reinterpret_cast<unsigned char *>(buffer),
                                         static_cast<unsigned long>(buffer_size),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG | 
                                         (use_buffer == use_entropy_in_buffer::yes ? BCRYPT_RNG_USE_ENTROPY_IN_BUFFER : 0)) };
        return status;
    }

    template <typename T> 
    [[nodiscard]]
    inline NTSTATUS try_generate_random(T *v,
                                        use_entropy_in_buffer use_buffer = use_entropy_in_buffer::no) noexcept {
        return try_generate_random(reinterpret_cast<char *>(v),
                                    sizeof(*v),
                                    use_buffer);
    }

    inline void generate_random(char* buffer,
                                size_t buffer_size,
                                use_entropy_in_buffer use_buffer = use_entropy_in_buffer::no) {
        NTSTATUS status{ try_generate_random( buffer,
                                              static_cast<unsigned long>(buffer_size)) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGenRandom failed");
        }
    }

    template <typename T>
    inline T generate_random() {
        T v;
        generate_random(reinterpret_cast<char*>(&v),
                        sizeof(v),
                        use_entropy_in_buffer::no);
        return v;
    }

    template<typename T>
    struct property_impl {
    protected:

        [[nodiscard]]
        NTSTATUS try_get_property(wchar_t const* property_name, 
                                  char *buffer, 
                                  size_t buffer_size, 
                                  size_t *rezult_size) const noexcept {
            unsigned long tmp_rezult_size{ 0 };
            NTSTATUS status{ BCryptGetProperty(get_object_handle(),
                                               property_name,
                                               reinterpret_cast<unsigned char *>(buffer),
                                               static_cast<unsigned long>(buffer_size),
                                               &tmp_rezult_size,
                                               0) };
            *rezult_size = tmp_rezult_size;
            return status;
        }

        [[nodiscard]]
        NTSTATUS try_get_property(wchar_t const* property_name, 
                                  hcrypt::buffer *buffer) const noexcept {
            NTSTATUS status{ STATUS_SUCCESS };
            for (;;) {
                size_t rezult_size{ 0 };
                bool empty_buffer{ buffer->empty() };
                status = try_get_property(property_name,
                                            empty_buffer ? nullptr : buffer->data(),
                                            empty_buffer ? 0 : buffer->size(),
                                            &rezult_size);
                if (NT_SUCCESS(status)) {
                    if (rezult_size <= buffer->size()) {
                        status = hcrypt::try_resize(buffer, rezult_size);
                        break;
                    } else {
                        status = hcrypt::try_resize(buffer, rezult_size);
                    }
                } else if (STATUS_BUFFER_TOO_SMALL == status) {
                    status = hcrypt::try_resize(buffer, rezult_size);
                } else {
                    break;
                }
            }
            return status;
        }

        [[nodiscard]]
        NTSTATUS try_get_property(wchar_t const* property_name, 
                                  std::wstring *buffer) const noexcept {
            
            NTSTATUS status{ STATUS_SUCCESS };
            
            for (;;) {
                size_t rezult_size{ 0 };
                bool empty_buffer{ buffer->empty() };
                status = try_get_property(property_name,
                                            empty_buffer ? nullptr : reinterpret_cast<char *>(buffer->data()),
                                            empty_buffer ? 0 : buffer->size() * sizeof(wchar_t),
                                            &rezult_size);
                if (NT_SUCCESS(status)) {
                    if (rezult_size <= (buffer->size() * sizeof(wchar_t))) {
                        //
                        // Remove extra terminating 0
                        //
                        status = hcrypt::try_resize(buffer, (rezult_size / sizeof(wchar_t)) - 1);
                        break;
                    } else {
                        status = hcrypt::try_resize(buffer, (rezult_size / sizeof(wchar_t)));
                    }
                } else if (STATUS_BUFFER_TOO_SMALL == status) {
                    status = hcrypt::try_resize(buffer, rezult_size / sizeof(wchar_t));
                } else {
                    break;
                }
            }
            return status;
        }

        template<typename T>
        [[nodiscard]]
        NTSTATUS try_get_property(wchar_t const* property_name, 
                                  T *value,
                                  size_t *result_size = nullptr) const noexcept {
            static_assert(std::is_pod_v<T>);
            size_t tmp_result_size{ 0 };
            NTSTATUS status{ try_get_property(property_name,
                                              reinterpret_cast<char *>(value),
                                              sizeof (*value),
                                              &tmp_result_size) };
            BCRYPT_CODDING_ERROR_IF(sizeof(*value) < tmp_result_size);
            if (result_size) {
                *result_size = tmp_result_size;
            }
            return status;
        }

        hcrypt::buffer get_property_as_buffer(wchar_t const* property_name,
                                              size_t default_buffer_size = 256) const {
            hcrypt::buffer b(default_buffer_size);
            NTSTATUS status{try_get_property(property_name, 
                                             &b)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGetProperty failed");
            }
            return b;
        }

        std::wstring get_property_as_string(wchar_t const* property_name, 
                                            size_t default_buffer_size = 256) const {
            std::wstring b(default_buffer_size, 0);
            NTSTATUS status{try_get_property(property_name, 
                                             &b)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGetProperty failed");
            }
            return b;
        }

        template <typename T>
        T get_property_as(wchar_t const* property_name) const {
            T value{};
            NTSTATUS status{try_get_property<T>(property_name, 
                                                &value)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGetProperty failed");
            }
            return value;
        }

        template <typename T>
        size_t get_property(wchar_t const* property_name,
                            T *value) const {
            size_t property_size{ 0 };
            NTSTATUS status{try_get_property(property_name, 
                                             &value,
                                             &property_size)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGetProperty failed");
            }
            return property_size;
        }

        [[nodiscard]]
        NTSTATUS try_set_property(wchar_t const* property_name, 
                                  char const *buffer,
                                  size_t buffer_size) {
            NTSTATUS status{ BCryptSetProperty(get_object_handle(),
                                               property_name,
                                               reinterpret_cast<unsigned char *>(const_cast<char *>(buffer)),
                                               static_cast<unsigned long>(buffer_size),
                                               0) };
            return status;
        }

        [[nodiscard]]
        NTSTATUS try_set_property(wchar_t const* property_name, 
                                  hcrypt::buffer const &buffer) {
            NTSTATUS status{ try_set_property(property_name,
                                              const_cast<unsigned char *>(buffer.data()),
                                              static_cast<unsigned long>(buffer.size())) };
            return status;
        }

        [[nodiscard]]
        NTSTATUS try_set_property(wchar_t const* property_name, 
                                  std::wstring const &buffer) {
            NTSTATUS status{ try_set_property(property_name,
                                              const_cast<unsigned char*>(buffer.data()),
                                              static_cast<unsigned long>(buffer.size() * sizeof(wchar_t))) };
            return status;
        }

        template <typename T>
        [[nodiscard]]
        NTSTATUS try_set_property(wchar_t const* property_name,
                                  T const &value) {
            NTSTATUS status{ try_set_property(property_name,
                                              &value,
                                              sizeof(value)) };
            return status;
        }

        void set_property(wchar_t const* property_name, 
                          char const *buffer,
                          size_t buffer_size) {
            NTSTATUS status{try_set_property(property_name,
                                             buffer,
                                             buffer_size)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptSetProperty failed");
            }
        }

        template <typename T>
        void set_property(wchar_t const* property_name, 
                          T const &value) {
            NTSTATUS status{try_set_property(property_name,
                                             value)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptSetProperty failed");
            }
        }

        BCRYPT_HANDLE get_object_handle() const {
            return static_cast<T const *>(this)->get_handle();
        }

    public:

        [[nodiscard]]
        NTSTATUS try_get_name(std::wstring* name) const noexcept {
            return try_get_property(BCRYPT_ALGORITHM_NAME, name);
        }

        std::wstring get_name() const {
            return get_property_as_string(BCRYPT_ALGORITHM_NAME);
        }

        [[nodiscard]]
        NTSTATUS try_get_block_length(unsigned long *value) const noexcept {
            return try_get_property(BCRYPT_BLOCK_LENGTH, value);
        }

        unsigned long get_block_length() const {
            return get_property_as<unsigned long>(BCRYPT_BLOCK_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_chaining_mode(std::wstring* name) const noexcept {
            return try_get_property(BCRYPT_CHAINING_MODE, name);
        }

        [[nodiscard]]
        NTSTATUS try_set_chaining_mode(std::wstring_view  const &new_mode) {
            return try_set_property(BCRYPT_CHAINING_MODE,
                                    reinterpret_cast<char const *>(new_mode.data()),
                                    new_mode.size());
        }

        std::wstring get_chaining_mode() const {
            return get_property_as_string(BCRYPT_CHAINING_MODE);
        }

        void set_chaining_mode(std::wstring_view  const& new_mode) {
            set_property(BCRYPT_CHAINING_MODE,
                         reinterpret_cast<char const*>(new_mode.data()),
                         new_mode.size());
        }

        [[nodiscard]]
        NTSTATUS try_get_block_size_list(hcrypt::buffer *b) const noexcept {
            return try_get_property(BCRYPT_BLOCK_SIZE_LIST, b);
        }

        hcrypt::buffer get_block_size_list() const {
            return get_property_as_buffer(BCRYPT_BLOCK_SIZE_LIST);
        }

        [[nodiscard]]
        NTSTATUS try_get_dh_parameters(hcrypt::buffer* b) const noexcept {
            return try_get_property(BCRYPT_DH_PARAMETERS, b);
        }

        [[nodiscard]]
        NTSTATUS try_set_dh_parameters(BCRYPT_DH_PARAMETER_HEADER const *b, size_t length_in_bytes) noexcept {
            return try_set_property(BCRYPT_DH_PARAMETERS, 
                                    reinterpret_cast<char const *>(b),
                                    length_in_bytes);
        }

        hcrypt::buffer get_dh_parameters() const {
            return get_property_as_buffer(BCRYPT_DH_PARAMETERS);
        }

        void set_dh_parameters(BCRYPT_DH_PARAMETER_HEADER const* b, size_t length_in_bytes) noexcept {
            set_property(BCRYPT_DH_PARAMETERS,
                         reinterpret_cast<char const*>(b),
                         length_in_bytes);
        }

        [[nodiscard]]
        NTSTATUS try_get_dsa_parameters(BCRYPT_DSA_PARAMETER_HEADER_V2* b) const noexcept {
            return try_get_property(BCRYPT_DSA_PARAMETERS, b);
        }

        [[nodiscard]]
        NTSTATUS try_set_dsa_parameters(BCRYPT_DSA_PARAMETER_HEADER_V2 const &b) noexcept {
            return try_set_property(BCRYPT_DSA_PARAMETERS, b);
        }

        BCRYPT_DSA_PARAMETER_HEADER_V2 get_dsa_parameters() const {
            return get_property_as<BCRYPT_DSA_PARAMETER_HEADER_V2>(BCRYPT_DSA_PARAMETERS);
        }

        void set_dsa_parameters(BCRYPT_DSA_PARAMETER_HEADER_V2 const& b) {
            set_property(BCRYPT_DSA_PARAMETERS, b);
        }

        [[nodiscard]]
        NTSTATUS try_get_effective_key_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_EFFECTIVE_KEY_LENGTH, value);
        }

        unsigned long get_effective_key_length() const {
            return get_property_as<unsigned long>(BCRYPT_EFFECTIVE_KEY_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_hash_block_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_HASH_BLOCK_LENGTH, value);
        }

        unsigned long get_hash_block_length() const {
            return get_property_as<unsigned long>(BCRYPT_HASH_BLOCK_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_hash_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_HASH_LENGTH, value);
        }

        unsigned long get_hash_length() const {
            return get_property_as<unsigned long>(BCRYPT_HASH_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_oid_list(hcrypt::buffer *b) const noexcept {
            return try_get_property(BCRYPT_HASH_OID_LIST, b);
        }

        hcrypt::buffer get_oid_list() const {
            return get_property_as_buffer(BCRYPT_HASH_OID_LIST);
        }

        [[nodiscard]]
        NTSTATUS try_get_initialization_vector(hcrypt::buffer *b) const noexcept {
            return try_get_property(BCRYPT_INITIALIZATION_VECTOR, b);
        }

        hcrypt::buffer get_initialization_vector() const {
            return get_property_as_buffer(BCRYPT_INITIALIZATION_VECTOR);
        }

        [[nodiscard]]
        NTSTATUS try_get_key_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_KEY_LENGTH, value);
        }

        unsigned long get_key_length() const {
            return get_property_as<unsigned long>(BCRYPT_KEY_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_key_lengts(BCRYPT_KEY_LENGTHS_STRUCT* b) const noexcept {
            return try_get_property(BCRYPT_KEY_LENGTHS, b);
        }

        BCRYPT_KEY_LENGTHS_STRUCT get_key_lengts() const {
            return get_property_as<BCRYPT_KEY_LENGTHS_STRUCT>(BCRYPT_KEY_LENGTHS);
        }

        [[nodiscard]]
        NTSTATUS try_get_key_object_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_OBJECT_LENGTH, value);
        }

        unsigned long get_key_object_length() const {
            return get_property_as<unsigned long>(BCRYPT_OBJECT_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_key_strength(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_KEY_STRENGTH, value);
        }

        unsigned long get_key_strength() const {
            return get_property_as<unsigned long>(BCRYPT_KEY_STRENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_message_block_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_MESSAGE_BLOCK_LENGTH, value);
        }

        [[nodiscard]]
        NTSTATUS try_set_message_block_length(unsigned long value) noexcept {
            return try_set_property(BCRYPT_MESSAGE_BLOCK_LENGTH, value);
        }

        unsigned long get_message_block_length() const {
            return get_property_as<unsigned long>(BCRYPT_MESSAGE_BLOCK_LENGTH);
        }

        void set_message_block_length(unsigned long value) {
            set_property(BCRYPT_MESSAGE_BLOCK_LENGTH, value);
        }

        [[nodiscard]]
        NTSTATUS try_get_multi_object_length(hcrypt::buffer *b) const noexcept {
            return try_get_property(BCRYPT_MULTI_OBJECT_LENGTH, b);
        }

        hcrypt::buffer get_multi_object_length() const {
            return get_property_as_buffer(BCRYPT_MULTI_OBJECT_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_object_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_OBJECT_LENGTH, value);
        }

        unsigned long get_object_length() const {
            return get_property_as<unsigned long>(BCRYPT_OBJECT_LENGTH);
        }

        [[nodiscard]]
        NTSTATUS try_get_padding_schemes(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_PADDING_SCHEMES, value);
        }

        unsigned long get_padding_schemes() const {
            return get_property_as<unsigned long>(BCRYPT_PADDING_SCHEMES);
        }

        [[nodiscard]]
        NTSTATUS try_get_signature_length(unsigned long* value) const noexcept {
            return try_get_property(BCRYPT_SIGNATURE_LENGTH, value);
        }

        unsigned long get_signature_length() const {
            return get_property_as<unsigned long>(BCRYPT_SIGNATURE_LENGTH);
        }
    };

    BCRUPT_PROPERTY_DECL(algorithm_name,        BCRYPT_ALGORITHM_NAME,        wchar_t*,                                   std::wstring,          true,  true);
    BCRUPT_PROPERTY_DECL(block_length,          BCRYPT_BLOCK_LENGTH,          unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(block_size_list,       BCRYPT_BLOCK_SIZE_LIST,       unsigned long*,                             hcrypt::buffer ,       true,  true); //
    BCRUPT_PROPERTY_DECL(chaining_mode,         BCRYPT_CHAINING_MODE,         wchar_t*,                                   std::wstring,          true,  true);
    BCRUPT_PROPERTY_DECL(dh_parameters,         BCRYPT_DH_PARAMETERS,         hcrypt::buffer,                             hcrypt::buffer ,       true,  false);
    BCRUPT_PROPERTY_DECL(dsa_parameters,        BCRYPT_DSA_PARAMETERS,        BCRYPT_DSA_PARAMETER_HEADER_V2,             hcrypt::buffer ,       true,  false);
    BCRUPT_PROPERTY_DECL(effective_key_length,  BCRYPT_EFFECTIVE_KEY_LENGTH,  unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(hash_block_length,     BCRYPT_HASH_BLOCK_LENGTH,     unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(hash_length,           BCRYPT_HASH_LENGTH,           unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(hash_oid_list,         BCRYPT_HASH_OID_LIST,         BCRYPT_OID_LIST*,                           hcrypt::buffer ,       false, true);
    BCRUPT_PROPERTY_DECL(initialization_vector, BCRYPT_INITIALIZATION_VECTOR, char*,                                      hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(key_length,            BCRYPT_KEY_LENGTH,            unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(key_lengths,           BCRYPT_KEY_LENGTHS,           BCRYPT_KEY_LENGTHS_STRUCT,                  hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(key_object_lengths,    BCRYPT_OBJECT_LENGTH ,        unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(key_strength,          BCRYPT_KEY_STRENGTH,          unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(message_block_length,  BCRYPT_MESSAGE_BLOCK_LENGTH,  unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(multi_object_length,   BCRYPT_MULTI_OBJECT_LENGTH,   BCRYPT_MULTI_OBJECT_LENGTH_STRUCT,          hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(object_length ,        BCRYPT_OBJECT_LENGTH ,        unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(padding_schemes,       BCRYPT_PADDING_SCHEMES ,      unsigned long,                              hcrypt::buffer ,       true,  true);
    BCRUPT_PROPERTY_DECL(signature_length,      BCRYPT_SIGNATURE_LENGTH ,     unsigned long,                              hcrypt::buffer ,       false, true);

    constexpr inline size_t dh_algorithm_key_size_min{ 512 };
    constexpr inline size_t dh_algorithm_key_size_multiplier{ 64 };
    constexpr inline size_t dh_algorithm_key_size_max{ 4096 };
    
    constexpr inline size_t dsa_algorithm_key_size_min{ 512 };
    constexpr inline size_t dsa_algorithm_key_size_multiplier{ 64 };
    constexpr inline size_t dsa_algorithm_key_size_max_before_win_8{ 1024 };
    constexpr inline size_t dsa_algorithm_key_size_max{ 3072 };

    constexpr inline size_t ecdh_p256_algorithm_size_key_size{ 256 };
    constexpr inline size_t ecdh_p384_algorithm_key_size{ 384 };
    constexpr inline size_t ecdh_p521_algorithm_key_size{ 521 };
    
    constexpr inline size_t ecdsa_p256_algorithm_key_size{ 256 };
    constexpr inline size_t ecdsa_p384_algorithm_key_size{ 384 };
    constexpr inline size_t ecdsa_p521_algorithm_key_size{ 521 };

    constexpr inline size_t rsa_algorithm_key_size_min{ 512 };
    constexpr inline size_t rsa_algorithm_key_size_multiplier{ 64 };
    constexpr inline size_t rsa_algorithm_key_size_max{ 16384 };

    class key;
    class hash;
    class secret;
    class algorithm_provider;

    class hash : public property_impl<hash> {

    public:

        friend class algorithm_provider;

        using handle_t = BCRYPT_HASH_HANDLE;

        hash() noexcept = default;

        hash(hash const &other) {
            hash duplicated_hash{ other.duplicate() };
            swap(duplicated_hash);
        };

        hash& operator=(hash const &other) {
            if (this != &other) {
                hash duplicated_hash{ other.duplicate() };
                swap(duplicated_hash);
            }
            return *this;
        }

        hash(hash &&other) noexcept
            : h_(other.h_) 
            , b_(std::move(other.b_)) {
            other.h_ = nullptr;
        }

        hash& operator=(hash &&other) noexcept {
            if (this != &other) {
                close();
                b_ = std::move(other.b_);
                h_ = other.h_;
                other.h_ = nullptr;
            }
            return *this;
        }

        ~hash() noexcept {
            close();
        }

        BCRYPT_HASH_HANDLE get_handle() const {
            return h_;
        }

        void swap(hash &other) noexcept {
            BCRYPT_HASH_HANDLE h{ h_ };
            hcrypt::buffer b{ b_ };
            h_ = other.h_;
            b_ = other.b_;
            other.h_ = h;
            other.b_ = b;
        }

        bool is_valid() const noexcept {
            return h_ != nullptr;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        [[nodiscard]]
        NTSTATUS try_duplicate_to(hash *hash) const noexcept {
            NTSTATUS status{ STATUS_SUCCESS };
            if (hash != this) {
                
                unsigned long hash_size{ 0 };
                status = try_get_object_length(&hash_size);

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                hcrypt::buffer b;
                status = hcrypt::try_resize(b, hash_size);

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                BCRYPT_HASH_HANDLE h{ nullptr };
                
                status = BCryptDuplicateHash(h_,
                                                &h,
                                                reinterpret_cast<unsigned char *>(b.data()),
                                                static_cast<unsigned long>(b.size()),
                                                0);

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                hash->close();
                hash->h_ = h;
                hash->b_ = std::move(b);
            }
            return status;
        }

        hash duplicate() const {
            
            hash hash_duplicate;

            hcrypt::buffer b;
            b.resize(get_object_length());

            BCRYPT_HASH_HANDLE h{ nullptr };

            NTSTATUS status{ BCryptDuplicateHash(h_,
                                                 &h,
                                                 reinterpret_cast<unsigned char*>(b.data()),
                                                 static_cast<unsigned long>(b.size()),
                                                 0) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDuplicateHash failed");
            }

            hash_duplicate.h_ = h;
            hash_duplicate.b_ = std::move(b);

            return hash_duplicate;
        }

        void close() noexcept {
            if (is_valid()) {
                NTSTATUS status{ BCryptDestroyHash(h_) };
                b_.clear();
                BCRYPT_CODDING_ERROR_IF_NOT(NT_SUCCESS(status));
            }
        }

        [[nodiscard]]
        NTSTATUS try_hash_data(char const *buffer,
                               size_t buffer_length) {
            return BCryptHashData(h_,
                                  reinterpret_cast<unsigned char *>(const_cast<char *>(buffer)),
                                  static_cast<unsigned long>(buffer_length),
                                  0);
        }

        void hash_data(char const* buffer,
                       size_t buffer_length) {
            NTSTATUS status{ try_hash_data(buffer,
                                           buffer_length) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptHashData failed");
            }

        }

        [[nodiscard]]
        NTSTATUS try_process_multiple_operations(BCRYPT_MULTI_HASH_OPERATION const *operations,
                                                 size_t operations_count) {
            return BCryptProcessMultiOperations(h_,
                                                BCRYPT_OPERATION_TYPE_HASH,
                                                reinterpret_cast<void *>(const_cast<BCRYPT_MULTI_HASH_OPERATION *>(operations)),
                                                static_cast<LONG>(operations_count * sizeof(BCRYPT_MULTI_HASH_OPERATION)),
                                                0);
        }

        template<size_t N>
        [[nodiscard]]
        NTSTATUS try_process_multiple_operations(BCRYPT_MULTI_HASH_OPERATION const (&operations)[N]) {
            return try_process_multiple_operations(operations,
                                                   N);
        }

        void process_multiple_operations(BCRYPT_MULTI_HASH_OPERATION const *operations,
                                         size_t operations_count) {
            NTSTATUS status{ try_process_multiple_operations(operations,
                                                              operations_count) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptProcessMultiOperations failed");
            }
        }

        template<size_t N>
        void process_multiple_operations(BCRYPT_MULTI_HASH_OPERATION const (&operations)[N]) {
            process_multiple_operations(operations,
                                        N);
        }

        [[nodiscard]]
        NTSTATUS try_finish(char *output,
                            size_t output_length) {
            
            return BCryptFinishHash(h_, 
                                    reinterpret_cast<unsigned char *>(output),
                                    static_cast<unsigned long>(output_length),
                                    0);
        }

        [[nodiscard]]
        NTSTATUS try_finish(hcrypt::buffer *b) {
            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long hash_length{ 0 };
            status = try_get_hash_length(&hash_length);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = hcrypt::try_resize(b, hash_length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = try_finish(b->data(),
                                b->size());

            if (!NT_SUCCESS(status)) {
                return status;
            }

            return status;
        }

        void finish(char *output,
                    size_t output_length) {

            NTSTATUS status{ try_finish(output,
                                        output_length) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptFinishHash failed");
            }
        }

        hcrypt::buffer finish() {
            hcrypt::buffer b;
            b.resize(get_hash_length());

            NTSTATUS status{ try_finish(b.data(),
                                        b.size()) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptFinishHash failed");
            }

            return b;
        }

    private:

        BCRYPT_HASH_HANDLE h_{ nullptr };
        hcrypt::buffer b_;
    };

    inline void swap(hash&l, hash&r) noexcept {
        l.swap(r);
    }
    
    class secret : public property_impl<secret> {

    public:

        friend class algorithm_provider;

        using handle_t = BCRYPT_SECRET_HANDLE;

        secret() noexcept = default;

        secret(secret const &other) = delete;
        secret& operator=(secret const& other) = delete;

        secret(secret &&other) noexcept
            : h_(other.h_) {
            other.h_ = nullptr;
        }

        secret& operator=(secret &&other) noexcept {
            if (this != &other) {
                close();
                h_ = other.h_;
                other.h_ = nullptr;
            }
            return *this;
        }

        ~secret() noexcept {
            close();
        }

        BCRYPT_SECRET_HANDLE get_handle() const {
            return h_;
        }

        void swap(secret &other) noexcept {
            BCRYPT_SECRET_HANDLE h{ h_ };
            h_ = other.h_;
            other.h_ = h;
        }

        bool is_valid() const noexcept {
            return h_ != nullptr;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        void attach(BCRYPT_SECRET_HANDLE h) noexcept {
            close();
            h_ = h;
        }

        BCRYPT_SECRET_HANDLE detach() noexcept {
            BCRYPT_SECRET_HANDLE h = h_;
            h_ = nullptr;
            return h;
        }

        void close() noexcept {
            if (is_valid()) {
                NTSTATUS status{ BCryptDestroySecret(h_) };
                BCRYPT_CODDING_ERROR_IF_NOT(NT_SUCCESS(status));
            }
        }

        [[nodiscard]]
        NTSTATUS try_derive_key(wchar_t const *key_derivation_function,
                                BCryptBufferDesc *parameters_list,
                                hcrypt::buffer *b) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long key_size{ 0 };
                
            status = BCryptDeriveKey(h_,
                                        key_derivation_function,
                                        parameters_list,
                                        nullptr,
                                        0,
                                        &key_size,
                                        0);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_KEY_HANDLE new_key{ nullptr };
            status = hcrypt::try_resize(b, key_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = BCryptDeriveKey(h_,
                                        key_derivation_function,
                                        parameters_list,
                                        reinterpret_cast<unsigned char *>(b->data()),
                                        static_cast<unsigned long>(b->size()),
                                        &key_size,
                                        0);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            return status;
        }

        hcrypt::buffer derive_key(wchar_t const *key_derivation_function,
                                  BCryptBufferDesc *parameters_list = nullptr) {

            NTSTATUS status{ STATUS_SUCCESS };
            unsigned long key_size{ 0 };
            hcrypt::buffer b;
                
            status = BCryptDeriveKey(h_,
                                     key_derivation_function,
                                     parameters_list,
                                     nullptr,
                                     0,
                                     &key_size,
                                     0);

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDeriveKey failed to estimate key size");
            }

            b.resize(key_size);

            status = BCryptDeriveKey(h_,
                                     key_derivation_function,
                                     parameters_list,
                                     reinterpret_cast<unsigned char *>(b.data()),
                                     static_cast<unsigned long>(b.size()),
                                     &key_size,
                                     0);

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDeriveKey failed");
            }

            return b;
        }

    private:
        BCRYPT_SECRET_HANDLE h_{ nullptr };
    };

    inline void swap(secret&l, secret&r) noexcept {
        l.swap(r);
    }

    class key : public property_impl<key> {

    public:

        friend class algorithm_provider;

        using handle_t = BCRYPT_KEY_HANDLE;

        key() noexcept = default;

        key(key const &other) {
            key duplicated_key{ other.duplicate() };
            swap(duplicated_key);
        };

        key& operator=(key const &other) {
            if (this != &other) {
                key duplicated_key{ other.duplicate() };
                swap(duplicated_key);
            }
            return *this;
        }

        key(key &&other) noexcept
            : h_(other.h_) 
            , b_(std::move(other.b_)) {
            other.h_ = nullptr;
        }

        key& operator=(key &&other) noexcept {
            if (this != &other) {
                close();
                b_ = std::move(other.b_);
                h_ = other.h_;
                other.h_ = nullptr;
            }
            return *this;
        }

        ~key() noexcept {
            close();
        }

        BCRYPT_KEY_HANDLE get_handle() const {
            return h_;
        }

        void swap(key &other) noexcept {
            BCRYPT_KEY_HANDLE h{ h_ };
            hcrypt::buffer b{ b_ };
            h_ = other.h_;
            b_ = other.b_;
            other.h_ = h;
            other.b_ = b;
        }

        bool is_valid() const noexcept {
            return h_ != nullptr;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        [[nodiscard]]
        NTSTATUS try_duplicate_to(key *key) const noexcept {
            NTSTATUS status{ STATUS_SUCCESS };

            if (key != this) {
                
                unsigned long key_size{ 0 };
                status = try_get_key_object_length(&key_size);

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                hcrypt::buffer b;
                status = hcrypt::try_resize(b, key_size);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                BCRYPT_KEY_HANDLE h{ nullptr };
                
                status = BCryptDuplicateKey(h_,
                                            &h,
                                            reinterpret_cast<unsigned char *>(b.data()),
                                            static_cast<unsigned long>(b.size()),
                                            0);

                if (!NT_SUCCESS(status)) {
                    return status;
                }

                key->close();
                key->h_ = h;
                key->b_ = std::move(b);
            }

            return status;
        }

        key duplicate() const {
            
            key key_duplicate;

            hcrypt::buffer b;
            b.resize(get_key_object_length());

            BCRYPT_KEY_HANDLE h{ nullptr };

            NTSTATUS status{ BCryptDuplicateKey(h_,
                                                &h,
                                                reinterpret_cast<unsigned char*>(b.data()),
                                                static_cast<unsigned long>(b.size()),
                                                0) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDuplicateKey failed");
            }

            key_duplicate.h_ = h;
            key_duplicate.b_ = std::move(b);

            return key_duplicate;
        }

        void close() noexcept {
            if (is_valid()) {
                NTSTATUS status{ BCryptDestroyKey(h_) };
                b_.clear();
                BCRYPT_CODDING_ERROR_IF_NOT(NT_SUCCESS(status));
            }
        }

        [[nodiscard]]
        NTSTATUS try_finalize_key_pair() {
            NTSTATUS status{ BCryptFinalizeKeyPair(h_, 0) };
            return status;
        }

        void finalize_key_pair() {
            NTSTATUS status{ try_finalize_key_pair() };
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptFinalizeKeyPair failed");
            }

        }

        [[nodiscard]]
        NTSTATUS try_export_key(wchar_t const *blob_type,
                                BCRYPT_KEY_HANDLE export_key_protector,
                                hcrypt::buffer *b) noexcept {

            unsigned long buffer_size{ 0 };

            NTSTATUS status{ BCryptExportKey(h_,
                                             export_key_protector,
                                             blob_type,
                                             nullptr,
                                             0,
                                             &buffer_size,
                                             0) };
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = hcrypt::try_resize(b, buffer_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = BCryptExportKey(h_,
                                        export_key_protector,
                                        blob_type,
                                        b->empty() ? nullptr : reinterpret_cast<unsigned char*>(b->data()),
                                        b->empty() ? 0 : static_cast<unsigned long>(b->size()),
                                        &buffer_size,
                                        0);

            if (NT_SUCCESS(status)) {
                status = hcrypt::try_resize(b, buffer_size);
            }

            return status;
        }

        [[nodiscard]]
        NTSTATUS try_export_key(wchar_t const *blob_type,
                                key const & export_key_protector,
                                hcrypt::buffer *b) noexcept {
            return try_export_key(blob_type,
                                  export_key_protector.get_handle(),
                                  b);
        }

        hcrypt::buffer export_key(wchar_t const *blob_type,
                                 BCRYPT_KEY_HANDLE export_key_protector = nullptr) {

            hcrypt::buffer b;
            unsigned long buffer_size{ 0 };

            NTSTATUS status{ BCryptExportKey(h_,
                                                export_key_protector,
                                                blob_type,
                                                nullptr,
                                                0,
                                                &buffer_size,
                                                0) };
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptExportKey failed");
            }

            b.resize(buffer_size);

            status = BCryptExportKey(h_,
                                        export_key_protector,
                                        blob_type,
                                        b.empty() ? nullptr : reinterpret_cast<unsigned char*>(b.data()),
                                        b.empty() ? 0 : static_cast<unsigned long>(b.size()),
                                        &buffer_size,
                                        0);

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptExportKey failed");
            }

            b.resize(buffer_size);

            return b;
        }

        hcrypt::buffer export_key(wchar_t const* blob_type,
                                  key const & export_key_protector) {

            return export_key(blob_type,
                              export_key_protector.get_handle());
        }

        [[nodiscard]]
        NTSTATUS try_key_derivation(char *key_buffer,
                                    size_t key_buffer_length,
                                    size_t *generated_key_length,
                                    BCryptBufferDesc *parameter_list,
                                    unsigned long flags = 0) noexcept {

            ULONG generated_key_length_tmp{ 0 };

            NTSTATUS status{ BCryptKeyDerivation(h_,
                                                 parameter_list,
                                                 reinterpret_cast<unsigned char*>(key_buffer),
                                                 static_cast<unsigned long>(key_buffer_length),
                                                 &generated_key_length_tmp,
                                                 flags) };

            if (NT_SUCCESS(status)) {
                *generated_key_length = generated_key_length_tmp;
            }

            return status;
        }

        [[nodiscard]]
        NTSTATUS try_key_derivation(size_t desired_key_size,
                                    BCryptBufferDesc *parameter_list,
                                    unsigned long flags,
                                    hcrypt::buffer *b) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            size_t generated_key_size{ 0 };
            status = hcrypt::try_resize(b, desired_key_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = try_key_derivation(b->empty() ? nullptr : b->data(),
                                        b->empty() ? 0 : b->size(),
                                        &generated_key_size,
                                        parameter_list,
                                        flags);

            if (NT_SUCCESS(status)) {
                status = hcrypt::try_resize(b, generated_key_size);
                return status;
            } else {
                return status;
            }

            return status;
        }

        size_t key_derivation(char *key_buffer,
                              size_t key_buffer_length,
                              BCryptBufferDesc *parameter_list,
                              unsigned long flags = 0) {

            size_t generated_key_size{ 0 };

            NTSTATUS status{ try_key_derivation(key_buffer,
                                                key_buffer_length,
                                                &generated_key_size,
                                                parameter_list,
                                                flags) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptKeyDerivation failed");
            }

            return generated_key_size;
        }

        hcrypt::buffer key_derivation(size_t desired_key_size,
                                      BCryptBufferDesc *parameter_list = nullptr,
                                      unsigned long flags = 0) {
            hcrypt::buffer b;
            b.resize(desired_key_size);
            size_t generated_key_size{ 0 };

            NTSTATUS status{ try_key_derivation(b.empty() ? nullptr : b.data(),
                                                b.empty() ? 0 : b.size(),
                                                &generated_key_size,
                                                parameter_list,
                                                flags) };

            if (NT_SUCCESS(status)) {
                b.resize(generated_key_size);
            } else {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptKeyDerivation failed");
            }

            return b;
        }

        [[nodiscard]]
        NTSTATUS try_sign_hash(char const *hash_value_to_sign,
                               size_t hash_value_to_sign_size,
                               void *padding_info,
                               unsigned long flags,
                               char *signature_buffer,
                               size_t signature_buffer_length,
                               size_t *required_size) noexcept {
;
            unsigned long buffer_size{ 0 };

            NTSTATUS status{ BCryptSignHash(h_,
                                            padding_info,
                                            reinterpret_cast<unsigned char*>(const_cast<char*>(hash_value_to_sign)),
                                            static_cast<unsigned long>(hash_value_to_sign_size),
                                            reinterpret_cast<unsigned char*>(signature_buffer),
                                            static_cast<unsigned long>(signature_buffer_length),
                                            &buffer_size,
                                            flags) };

            if (NT_SUCCESS(status)) {
                *required_size = buffer_size;
            }

            return status;
        }

        [[nodiscard]]
        NTSTATUS try_sign_hash(char const *hash_value_to_sign,
                               size_t hash_value_to_sign_size,
                               void *padding_info,
                               unsigned long flags,
                               hcrypt::buffer *b) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            size_t buffer_size{ 0 };

            status = try_sign_hash( hash_value_to_sign,
                                    hash_value_to_sign_size,
                                    padding_info,
                                    flags,
                                    nullptr,
                                    0,
                                    &buffer_size);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = hcrypt::try_resize(b, buffer_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = try_sign_hash( hash_value_to_sign,
                                    hash_value_to_sign_size,
                                    padding_info,
                                    flags,
                                    b->empty() ? nullptr : b->data(),
                                    b->empty() ? 0 : b->size(),
                                    &buffer_size);

            if (NT_SUCCESS(status)) {
                status = hcrypt::try_resize(b, buffer_size);
            }

            return status;
        }

        hcrypt::buffer sign_hash(char const *hash_value_to_sign,
                                 size_t hash_value_to_sign_size,
                                 void* padding_info = nullptr,
                                 unsigned long flags = 0) {

            hcrypt::buffer b;
            size_t buffer_size{ 0 };

            NTSTATUS status{ try_sign_hash(hash_value_to_sign,
                                           hash_value_to_sign_size,
                                           padding_info,
                                           flags,
                                           nullptr,
                                           0,
                                           &buffer_size) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptSignHash failed");
            }

            b.resize(buffer_size);

            status = try_sign_hash( hash_value_to_sign,
                                    hash_value_to_sign_size,
                                    padding_info,
                                    flags,
                                    b.empty() ? nullptr : b.data(),
                                    b.empty() ? 0 : b.size(),
                                    &buffer_size);

            if (NT_SUCCESS(status)) {
                b.resize(buffer_size);
            } else {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptSignHash failed");
            }
            return b;
        }

        [[nodiscard]]
        NTSTATUS try_verify_signature(void const *padding_info,
                                      char *hash,
                                      size_t hash_size,
                                      char *signature,
                                      size_t signature_size,
                                      unsigned long flags = 0) noexcept {

            return BCryptVerifySignature(h_,
                                         const_cast<void*>(padding_info),
                                         reinterpret_cast<unsigned char*>(const_cast<char*>(hash)),
                                         static_cast<unsigned long>(hash_size),
                                         reinterpret_cast<unsigned char*>(const_cast<char*>(signature)),
                                         static_cast<unsigned long>(signature_size),
                                         flags);
        }

        [[nodiscard]]
        bool verify_signature(void const *padding_info,
                              char *hash,
                              size_t hash_size,
                              char *signature,
                              size_t signature_size,
                              unsigned long flags = 0) {

            NTSTATUS status = try_verify_signature(padding_info,
                                                   hash,
                                                   hash_size,
                                                   signature,
                                                   signature_size,
                                                   flags);

            if (!NT_SUCCESS(status)) {

                if (STATUS_INVALID_SIGNATURE == status) {
                    return false;
                } 

                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptVerifySignature failed");
            }

            return true;
        }

        [[nodiscard]]
        NTSTATUS try_encrypt(char const *input_buffer,
                             size_t encrypt_buffer_length,
                             void *padding_info,
                             char *initialization_vector,
                             size_t initialization_vector_length,
                             char *output,
                             size_t output_length,
                             size_t *output_expected_length,
                             unsigned long flags) {
            unsigned long output_expected_length_tmp{ 0 };
            NTSTATUS status{ BCryptEncrypt(h_,
                                           reinterpret_cast<unsigned char*>(const_cast<char*>(input_buffer)),
                                           static_cast<unsigned long>(encrypt_buffer_length),
                                           padding_info,
                                           reinterpret_cast<unsigned char*>(initialization_vector),
                                           static_cast<unsigned long>(initialization_vector_length),
                                           reinterpret_cast<unsigned char*>(output),
                                           static_cast<unsigned long>(output_length),
                                           &output_expected_length_tmp,
                                           flags) };
            
            *output_expected_length = output_expected_length_tmp;
            
            return status;
        }

        void encrypt(char const *input_buffer,
                     size_t encrypt_buffer_length,
                     void *padding_info,
                     char *initialization_vector,
                     size_t initialization_vector_length,
                     char *output,
                     size_t output_length,
                     size_t *output_expected_length,
                     unsigned long flags) {

            NTSTATUS status{ try_encrypt(input_buffer, 
                                         encrypt_buffer_length,
                                         padding_info,
                                         initialization_vector,
                                         initialization_vector_length,
                                         output,
                                         output_length,
                                         output_expected_length,
                                         flags) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptEncrypt failed");
            }
        }

        [[nodiscard]]
        NTSTATUS try_decrypt(char const *input_buffer,
                             size_t encrypt_buffer_length,
                             void *padding_info,
                             char *initialization_vector,
                             size_t initialization_vector_length,
                             char *output,
                             size_t output_length,
                             size_t *output_expected_length,
                             unsigned long flags) {
            unsigned long output_expected_length_tmp{ 0 };
            NTSTATUS status{ BCryptDecrypt(h_,
                                           reinterpret_cast<unsigned char*>(const_cast<char*>(input_buffer)),
                                           static_cast<unsigned long>(encrypt_buffer_length),
                                           padding_info,
                                           reinterpret_cast<unsigned char*>(initialization_vector),
                                           static_cast<unsigned long>(initialization_vector_length),
                                           reinterpret_cast<unsigned char*>(output),
                                           static_cast<unsigned long>(output_length),
                                           &output_expected_length_tmp,
                                           flags) };
            
            *output_expected_length = output_expected_length_tmp;
            
            return status;
        }

        [[nodiscard]]
        bool decrypt(char const *input_buffer,
                     size_t encrypt_buffer_length,
                     void *padding_info,
                     char *initialization_vector,
                     size_t initialization_vector_length,
                     char *output,
                     size_t output_length,
                     size_t *output_expected_length,
                     unsigned long flags) {

            NTSTATUS status{ try_decrypt(input_buffer, 
                                         encrypt_buffer_length,
                                         padding_info,
                                         initialization_vector,
                                         initialization_vector_length,
                                         output,
                                         output_length,
                                         output_expected_length,
                                         flags) };

            if (!NT_SUCCESS(status)) {

                if (STATUS_AUTH_TAG_MISMATCH == status) {
                    return false;
                }

                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDecrypt failed");
            }

            return true;
        }

    private:
        BCRYPT_KEY_HANDLE h_{ nullptr };
        hcrypt::buffer b_;
    };

    inline void swap(key &l, key &r) noexcept {
        l.swap(r);
    }

    [[nodiscard]]
    inline NTSTATUS try_create_secret(BCRYPT_KEY_HANDLE private_key,
                                      BCRYPT_KEY_HANDLE public_key,
                                      secret *s) noexcept {

        BCRYPT_SECRET_HANDLE h{ nullptr };
        
        NTSTATUS status{ BCryptSecretAgreement(private_key, public_key, &h, 0) };
        if (NT_SUCCESS(status)) {
            s->attach(h);
        }
        return status;
    }

    [[nodiscard]]
    inline NTSTATUS try_create_secret(key const &private_key,
                                      key const &public_key,
                                      secret *s) noexcept {

        return try_create_secret(private_key.get_handle(),
                                 public_key.get_handle(),
                                 s);
    }

    inline secret create_secret(BCRYPT_KEY_HANDLE private_key,
                                BCRYPT_KEY_HANDLE public_key ) {
        secret s;
        NTSTATUS status{ try_create_secret(private_key, 
                                           public_key, 
                                           &s) };
        if (!NT_SUCCESS(status)) {
            throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptSecretAgreement failed");
        }
        return s;
    }

    inline secret create_secret(key const &private_key,
                                key const &public_key ) {
        return create_secret(private_key.get_handle(), 
                             public_key.get_handle());
    }
    
    class algorithm_provider : public property_impl<algorithm_provider> {

    public:

        using handle_t = BCRYPT_ALG_HANDLE;

        algorithm_provider() noexcept = default;

        algorithm_provider(wchar_t const* algorithm,
                           wchar_t const* provider = nullptr,
                           unsigned long flags = 0) {
            open( algorithm,
                  provider,
                  flags);
        }       

        explicit algorithm_provider(BCRYPT_ALG_HANDLE h) noexcept 
            : h_(h) {
        }

        algorithm_provider(algorithm_provider const &) = delete;
        algorithm_provider& operator=(algorithm_provider const &) = delete;

        algorithm_provider(algorithm_provider &&other) noexcept 
            : h_(other.detach()) {
        }

        algorithm_provider & operator=(algorithm_provider &&other) noexcept {
            if (this != &other) {
                close();
                h_ = other.detach();
            }
            return *this;
        }

        ~algorithm_provider() noexcept {
            close();
        }

        BCRYPT_ALG_HANDLE get_handle() const {
            return h_;
        }

        BCRYPT_ALG_HANDLE detach() noexcept {
            BCRYPT_ALG_HANDLE h{ h_ };
            h_ = nullptr;
            return h;
        }

        void attach(BCRYPT_ALG_HANDLE h) noexcept {
            close();
            h_ = h;
        }

        void swap(algorithm_provider &other) noexcept {
            BCRYPT_ALG_HANDLE h{ h_ };
            h_ = other.h_;
            other.h_ = h;
        }

        bool is_valid() const noexcept {
            return h_ != nullptr;
        }

        explicit operator bool() const noexcept {
            return is_valid();
        }

        [[nodiscard]]
        NTSTATUS try_open(wchar_t const *algorithm,
                          wchar_t const *provider = nullptr,
                          unsigned long flags = 0) noexcept {
            close();
            NTSTATUS status{ BCryptOpenAlgorithmProvider(&h_,
                                                         algorithm,
                                                         provider,
                                                         flags) };
            return status;
        }

        void open(wchar_t const *algorithm,
                  wchar_t const *provider = nullptr,
                  unsigned long flags = 0) {
            NTSTATUS status{ try_open (algorithm,
                                       provider,
                                       flags)};
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptOpenAlgorithmProvider failed");
            }
        }

        void close() noexcept {
            if (is_valid()) {
                NTSTATUS status{ BCryptCloseAlgorithmProvider(h_, 0) };
                BCRYPT_CODDING_ERROR_IF_NOT(NT_SUCCESS(status));
            }
        }

        [[nodiscard]]
        NTSTATUS try_generate_symmetric_key(char const *secret, 
                                            size_t secret_length,
                                            key *k) noexcept {
            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long key_size{ 0 };
            status = try_get_key_object_length(&key_size);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            hcrypt::buffer b;
            status = hcrypt::try_resize(b, key_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_KEY_HANDLE key_handle{ nullptr };

            status = BCryptGenerateSymmetricKey(h_,
                                                &key_handle,
                                                reinterpret_cast<unsigned char *>(b.data()),
                                                static_cast<unsigned long>(b.size()),
                                                reinterpret_cast<unsigned char *>(const_cast<char *>(secret)),
                                                static_cast<unsigned long>(secret_length),
                                                0);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            k->close();
            k->h_ = key_handle;
            k->b_ = std::move(b);

            return status;
        }

        key generate_symmetric_key(char const *secret,
                                   size_t secret_length) {
            hcrypt::buffer b;
            b.resize(get_key_object_length());

            BCRYPT_KEY_HANDLE key_handle{ nullptr };

            NTSTATUS status{ BCryptGenerateSymmetricKey(h_,
                                                        &key_handle,
                                                        reinterpret_cast<unsigned char*>(b.data()),
                                                        static_cast<unsigned long>(b.size()),
                                                        reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                                                        static_cast<unsigned long>(secret_length),
                                                        0) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptDuplicateKey failed");
            }

            key new_key;

            new_key.h_ = key_handle;
            new_key.b_ = std::move(b);

            return new_key;
        }

        [[nodiscard]]
        NTSTATUS try_generate_empty_key_pair(size_t key_size, 
                                             key *k) noexcept {

            BCRYPT_KEY_HANDLE new_key{ nullptr };
            
            NTSTATUS status{ BCryptGenerateKeyPair(h_,
                                                   &new_key,
                                                   static_cast<unsigned long>(key_size),
                                                   0) };

            if (!NT_SUCCESS(status)) {
                return status;
            }

            k->close();
            k->h_ = new_key;

            return status;
        }

        key generate_empty_key_pair(size_t key_size) {

            BCRYPT_KEY_HANDLE new_key{ nullptr };
            
            NTSTATUS status{ BCryptGenerateKeyPair(h_,
                                                   &new_key,
                                                   static_cast<unsigned long>(key_size),
                                                   0) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGenerateKeyPair failed");
            }

            key k;
            k.h_ = new_key;

            return k;
        }

        [[nodiscard]]
        NTSTATUS try_import_symetric_key(BCRYPT_KEY_HANDLE import_key,
                                         wchar_t const *blob_type,
                                         char const *key_object,
                                         size_t key_object_size,
                                         key *k) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long key_size{ 0 };
            status = try_get_key_object_length(&key_size);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_KEY_HANDLE new_key{ nullptr };
            hcrypt::buffer b;
            status = hcrypt::try_resize(b, key_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = BCryptImportKey(h_,
                                     import_key,
                                     blob_type,
                                     &new_key,
                                     reinterpret_cast<unsigned char *>(const_cast<char *>(key_object)),
                                     static_cast<unsigned long>(key_object_size),
                                     reinterpret_cast<unsigned char *>(b.data()),
                                     static_cast<unsigned long>(b.size()),
                                     0);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            k->close();
            k->h_ = new_key;
            k->b_ = std::move(b);


            return status;
        }

        [[nodiscard]]
        NTSTATUS try_import_symetric_key(key const &import_key,
                                         wchar_t const *blob_type,
                                         char const *key_object,
                                         size_t key_object_size,
                                         key *k) noexcept {

            return try_import_symetric_key(import_key.get_handle(),
                                           blob_type,
                                           key_object,
                                           key_object_size,
                                           k);
        }

        key import_symetric_key(BCRYPT_KEY_HANDLE import_key,
                                wchar_t const *blob_type,
                                char const *key_object,
                                size_t key_object_size) {

            BCRYPT_KEY_HANDLE new_key{ nullptr };
            hcrypt::buffer b;
            b.resize(get_key_object_length());

            NTSTATUS status{ BCryptImportKey(h_,
                                             import_key,
                                             blob_type,
                                             &new_key,
                                             reinterpret_cast<unsigned char*>(const_cast<char*>(key_object)),
                                             static_cast<unsigned long>(key_object_size),
                                             reinterpret_cast<unsigned char*>(b.data()),
                                             static_cast<unsigned long>(b.size()),
                                             0) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptImportKey failed");
            }

            key k;
            k.h_ = new_key;
            k.b_ = std::move(b);

            return k;
        }

        key import_symetric_key(key const & import_key,
                                wchar_t const *blob_type,
                                char const *key_object,
                                size_t key_object_size) {

            return import_symetric_key(import_key.get_handle(),
                                       blob_type,
                                       key_object,
                                       key_object_size);
        }

        [[nodiscard]]
        NTSTATUS try_import_key_pair(wchar_t const *blob_type,
                                     char const *key_object,
                                     size_t key_object_size,
                                     BCRYPT_KEY_HANDLE import_key,
                                     unsigned long flags,
                                     key *k) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            BCRYPT_KEY_HANDLE new_key{ nullptr };

            status = BCryptImportKeyPair(h_,
                                         import_key,
                                         blob_type,
                                         &new_key,
                                         reinterpret_cast<unsigned char *>(const_cast<char *>(key_object)),
                                         static_cast<unsigned long>(key_object_size),
                                         flags);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            k->close();
            k->h_ = new_key;

            return status;
        }

        [[nodiscard]]
        NTSTATUS try_import_key_pair(wchar_t const *blob_type,
                                     char const *key_object,
                                     size_t key_object_size,
                                     key const &import_key,
                                     unsigned long flags,
                                     key *k) noexcept {

            return try_import_key_pair(blob_type,
                                       key_object,
                                       key_object_size,
                                       import_key.get_handle(),
                                       flags,
                                       k);
        }

        key import_key_pair(wchar_t const *blob_type,
                            char const *key_object,
                            size_t key_object_size,
                            BCRYPT_KEY_HANDLE import_key = nullptr,
                            unsigned long flags = 0) {

            BCRYPT_KEY_HANDLE new_key{ nullptr };

            NTSTATUS status{ BCryptImportKeyPair(h_,
                                                 import_key,
                                                 blob_type,
                                                 &new_key,
                                                 reinterpret_cast<unsigned char*>(const_cast<char*>(key_object)),
                                                 static_cast<unsigned long>(key_object_size),
                                                 flags) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptImportKeyPair failed");
            }

            key k;
            k.h_ = new_key;

            return k;
        }

        key import_key_pair(wchar_t const *blob_type,
                            char const *key_object,
                            size_t key_object_size,
                            key const & import_key,
                            unsigned long flags = 0) {

            return import_key_pair(blob_type,
                                   key_object,
                                   key_object_size,
                                   import_key.get_handle(),
                                   flags);
        }

        [[nodiscard]]
        NTSTATUS try_derive_key_PBKDF2(char const *password,
                                       size_t password_length,
                                       char const *salt,
                                       size_t salt_length,
                                       unsigned long long iterations_count,
                                       hcrypt::buffer *b) noexcept {

            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long key_size{ 0 };
            status = try_get_key_object_length(&key_size);

            if (!NT_SUCCESS(status)) {
                return status;
            }
                
            status = hcrypt::try_resize(b, key_size);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status =  BCryptDeriveKeyPBKDF2(h_,
                                            reinterpret_cast<unsigned char*>(const_cast<char*>(password)),
                                            static_cast<unsigned long>(password_length),
                                            reinterpret_cast<unsigned char*>(const_cast<char*>(salt)),
                                            static_cast<unsigned long>(salt_length),
                                            iterations_count,
                                            b->empty() ? nullptr : reinterpret_cast<unsigned char*>(b->data()),
                                            static_cast<unsigned long>(b->size()),
                                            0);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            return status;
        }

        hcrypt::buffer derive_key_PBKDF2(char const *password,
                                         size_t password_length,
                                         char const *salt,
                                         size_t salt_length,
                                         unsigned long long iterations_count = 1000) {
            hcrypt::buffer b;
            b.resize(get_key_object_length());

            NTSTATUS status =  BCryptDeriveKeyPBKDF2(h_,
                                                     reinterpret_cast<unsigned char*>(const_cast<char*>(password)),
                                                     static_cast<unsigned long>(password_length),
                                                     reinterpret_cast<unsigned char*>(const_cast<char*>(salt)),
                                                     static_cast<unsigned long>(salt_length),
                                                     iterations_count,
                                                     b.empty() ? nullptr : reinterpret_cast<unsigned char*>(b.data()),
                                                     static_cast<unsigned long>(b.size()),
                                                     0);

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGenRandom failed");
            }

            return b;
        }

        [[nodiscard]]
        NTSTATUS try_create_hash(char const *secret,
                                 size_t secret_length,
                                 unsigned long flags,
                                 hash *hash) {
            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long object_length{ 0 };
            status = try_get_object_length(&object_length);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            hcrypt::buffer b;
            status = hcrypt::try_resize(b, object_length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_HASH_HANDLE h{ nullptr };

            status = BCryptCreateHash(h_,
                &h,
                reinterpret_cast<unsigned char*>(b.data()),
                static_cast<unsigned long>(b.size()),
                reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                static_cast<unsigned long>(secret_length),
                flags);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            hash->close();
            hash->h_ = h;
            hash->b_ = std::move(b);

            return status;
        }

        hash create_hash(char const *secret = nullptr,
                         size_t secret_length = 0,
                         unsigned long flags = BCRYPT_HASH_REUSABLE_FLAG) {
            hash h;

            hcrypt::buffer b;
            b.resize(get_object_length());

            BCRYPT_HASH_HANDLE new_h{ nullptr };

            NTSTATUS status{ BCryptCreateHash(h_,
                                              &new_h,
                                              reinterpret_cast<unsigned char*>(b.data()),
                                              static_cast<unsigned long>(b.size()),
                                              reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                                              static_cast<unsigned long>(secret_length),
                                              flags) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptCreateHash failed");
            }

            h.h_ = new_h;
            h.b_ = std::move(b);

            return h;
        }

        [[nodiscard]]
        NTSTATUS try_create_multihash(unsigned long numer_of_hashes,
                                      char const *secret,
                                      size_t secret_length,
                                      unsigned long flags,
                                      hash *hash) {
            NTSTATUS status{ STATUS_SUCCESS };

            hcrypt::buffer multiobject_info;
            status = try_get_multi_object_length(&multiobject_info);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const* multi_object_length{
                reinterpret_cast<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const*>(multiobject_info.data()) };

            unsigned long multiobject_length{ multi_object_length->cbPerObject + (multi_object_length->cbPerElement * numer_of_hashes) };

            hcrypt::buffer b;
            status = hcrypt::try_resize(b, multiobject_length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            BCRYPT_HASH_HANDLE h{ nullptr };

            status = BCryptCreateMultiHash(h_,
                                           &h,
                                           numer_of_hashes,
                                           reinterpret_cast<unsigned char*>(b.data()),
                                           static_cast<unsigned long>(b.size()),
                                           reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                                           static_cast<unsigned long>(secret_length),
                                           flags);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            hash->close();
            hash->h_ = h;
            hash->b_ = std::move(b);

            return status;
        }

        hash create_multihash(unsigned long numer_of_hashes,
                              char const *secret = nullptr,
                              size_t secret_length = 0,
                              unsigned long flags = BCRYPT_HASH_REUSABLE_FLAG) {
            hcrypt::buffer multiobject_info{ get_multi_object_length() };

            BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const* multi_object_length{
                reinterpret_cast<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT const*>(multiobject_info.data()) };

            unsigned long multiobject_length{ multi_object_length->cbPerObject + (multi_object_length->cbPerElement * numer_of_hashes) };

            hcrypt::buffer b;
            b.resize(multiobject_length);

            BCRYPT_HASH_HANDLE new_h{ nullptr };

            NTSTATUS status{ BCryptCreateMultiHash(h_,
                                                   &new_h,
                                                   numer_of_hashes,
                                                   reinterpret_cast<unsigned char*>(b.data()),
                                                   static_cast<unsigned long>(b.size()),
                                                   reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                                                   static_cast<unsigned long>(secret_length),
                                                   flags) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptCreateMultiHash failed");
            }

            hash h;
            h.h_ = new_h;
            h.b_ = std::move(b);

            return h;
        }

        [[nodiscard]]
        NTSTATUS try_hash_data(char const *secret,
                               size_t secret_length,
                               char const *input,
                               size_t input_length,
                               char *hash_buffer,
                               size_t hash_buffer_length) noexcept {
            return BCryptHash(h_,
                              reinterpret_cast<unsigned char*>(const_cast<char*>(secret)),
                              static_cast<unsigned long>(secret_length),
                              reinterpret_cast<unsigned char*>(const_cast<char*>(input)),
                              static_cast<unsigned long>(input_length),
                              reinterpret_cast<unsigned char*>(const_cast<char*>(hash_buffer)),
                              static_cast<unsigned long>(hash_buffer_length));
        }

        [[nodiscard]]
        NTSTATUS try_hash_data(char const *secret,
                               size_t secret_length,
                               char const *input,
                               size_t input_length,
                               hcrypt::buffer *b) noexcept {
            NTSTATUS status{ STATUS_SUCCESS };

            unsigned long hash_length{ 0 };
            status = try_get_hash_length(&hash_length);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = hcrypt::try_resize(b, hash_length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = try_hash_data(secret,
                                   secret_length,
                                   input,
                                   input_length,
                                   b->data(),
                                   b->size());

            if (!NT_SUCCESS(status)) {
                return status;
            }

            return status;
        }

        void hash_data(char const *secret,
                       size_t secret_length,
                       char const *input,
                       size_t input_length,
                       char *hash_buffer,
                       size_t hash_buffer_length) {

            NTSTATUS status{ try_hash_data(secret,
                                           secret_length,
                                           input,
                                           input_length,
                                           hash_buffer,
                                           hash_buffer_length) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptHash failed");
            }
        }

        hcrypt::buffer hash_data(char const *secret,
                                 size_t secret_length,
                                 char const *input,
                                 size_t input_length) {
            hcrypt::buffer b;
            b.resize(get_hash_length());

            NTSTATUS status{ status = try_hash_data(secret,
                                                    secret_length,
                                                    input,
                                                    input_length,
                                                    b.data(),
                                                    b.size()) };

            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptHash failed");
            }

            return b;
        }

        [[nodiscard]]
        NTSTATUS try_generate_random(char *buffer,
                                     size_t buffer_size,
                                     use_entropy_in_buffer use_buffer = use_entropy_in_buffer::no) noexcept {
            NTSTATUS status{ BCryptGenRandom(h_,
                                             reinterpret_cast<unsigned char*>(buffer),
                                             static_cast<unsigned long>(buffer_size),
                                             use_buffer == use_entropy_in_buffer::yes ? BCRYPT_RNG_USE_ENTROPY_IN_BUFFER : 0) };
            return status;
        }

        template <typename T> 
        [[nodiscard]]
        NTSTATUS try_generate_random(T *v, 
                                     use_entropy_in_buffer use_buffer = use_entropy_in_buffer::no) noexcept {
            return try_generate_random(reinterpret_cast<char *>(v),
                                       sizeof(*v),
                                       use_buffer);
        }

        void generate_random(char* buffer,
                             size_t buffer_size,
                             use_entropy_in_buffer uese_buffer = use_entropy_in_buffer::no) {
            NTSTATUS status{ try_generate_random( buffer,
                                                  static_cast<unsigned long>(buffer_size)) };
            if (!NT_SUCCESS(status)) {
                throw BCRYPT_MAKE_SYSTEM_ERROR(status, "BCryptGenRandom failed");
            }
        }

        template <typename T>
        T generate_random() {
            T v;
            generate_random(reinterpret_cast<char*>(&v),
                            sizeof(v),
                            use_entropy_in_buffer::no);
            return v;
        }

    private:
        BCRYPT_ALG_HANDLE h_{ nullptr };
    };

    inline void swap(algorithm_provider &l, algorithm_provider &r) noexcept {
        l.swap(r);
    }
    

}