#pragma once

#include "hcrypt_common.hpp"

#include <wincred.h>

#pragma comment(lib, "Advapi32.lib")

namespace credman {

    template<typename T = void>
    class cred_ptr {
    public:
        cred_ptr() noexcept = default;

        cred_ptr(cred_ptr const &) noexcept = delete;
        cred_ptr &operator=(cred_ptr const &) noexcept = delete;

        explicit cred_ptr(T *b) noexcept
            : b_{b} {
        }

        cred_ptr(cred_ptr &&other) noexcept
            : b_{other.b_} {
            other.b_ = nullptr;
        }

        cred_ptr &operator=(cred_ptr &&other) noexcept {
            b_ = other.b_;
            other.b_ = nullptr;
            return *this;
        }

        ~cred_ptr() noexcept {
            free();
        }

        using value_type = T;
        using reference = T &;
        using const_reference = T const &;
        using pointer = T *;
        using const_pointer = T const *;
        using size_type = unsigned long;

        void swap(cred_ptr &other) noexcept {
            T *tmp = b_;
            b_ = other.b_;
            other.b_ = tmp;
        }

        void free() noexcept {
            if (b_) {
                CredFree(static_cast<void *>(b_));
                b_ = nullptr;
            }
        }

        void attach(T *b) noexcept {
            if (b != b_) {
                free();
                b_ = b;
            }
        }

        T *detach() noexcept {
            return b_;
        }

        operator bool() const noexcept {
            return b_ != nullptr;
        }

        T *get() const {
            return b_;
        }

        T &operator*() const noexcept {
            return *b_;
        }

        T *operator->() const noexcept {
            return b_;
        }

    private:
        T *b_{nullptr};
    };

    template<typename T>
    void swap(cred_ptr<T> &lhs, cred_ptr<T> &rhs) {
        lhs.swap(rhs);
    }

    template<typename T>
    class cred_array {
    public:
        cred_array() noexcept = default;
        ~cred_array() noexcept = default;

        cred_array(cred_array &&) noexcept = default;
        cred_array &operator=(cred_array &&) noexcept = default;

        cred_array(cred_array const &) noexcept = delete;
        cred_array &operator=(cred_array const &) noexcept = delete;

        cred_array(unsigned long size, cred_ptr<T> creds)
            : size_{size}
            , creds_{creds} {
        }

        cred_array(unsigned long size, T **creds)
            : size_{size}
            , creds_{creds} {
        }

        using value_type = T;
        using reference = T &;
        using const_reference = T const &;
        using pointer = T *;
        using const_pointer = T const *;
        using size_type = unsigned long;

        [[nodiscard]] unsigned long size() const {
            return size_;
        }

        T **data() {
            return creds_.ptr();
        }

        T const *const *data() const {
            return creds_.ptr();
        }

        operator bool() const {
            return size_ != 0;
        }

        T &operator[](unsigned long idx) {
            BCRYPT_CODDING_ERROR_IF(idx >= size_);
            return *(creds_.get()[idx]);
        }

        T const &operator[](unsigned long idx) const {
            BCRYPT_CODDING_ERROR_IF(idx >= size_);
            return *(creds_.get()[idx]);
        }

        void swap(cred_array &other) {
            unsigned long tmp = size_;
            size_ = other.size_;
            other.size_ = tmp;
            creds_.swap(other.creds_);
        }

        void attach(unsigned long size, cred_ptr<T> creds) {
            size_ = size;
            creds_ = creds;
        }

        void attach(unsigned long size, T **creds) {
            size_ = size;
            creds_.attach(creds);
        }

        cred_ptr<T> detach() {
            return std::move(creds_);
        }

        template<typename U>
        class iterator_t {
            template<typename>
            friend class cred_array;

            template<typename V>
            iterator_t(unsigned long idx, cred_ptr<V *> *creds, bool /*tag*/)
                : idx_{idx}
                , creds_{reinterpret_cast<cred_ptr<T const *> *>(creds)} {
            }

        public:
            iterator_t() = default;
            iterator_t(iterator_t const &) = default;
            iterator_t(iterator_t &&) = default;
            ~iterator_t() = default;
            iterator_t &operator=(iterator_t const &) = default;
            iterator_t &operator=(iterator_t &&) = default;

            iterator_t(unsigned long idx, cred_ptr<U *> *creds)
                : idx_{idx}
                , creds_{creds} {
            }

            using difference_type = int;
            using value_type = U;
            using pointer = U *;
            using reference = U &;
            using iterator_category = std::random_access_iterator_tag;

            U &operator*() const noexcept {
                return *(creds_->get()[idx_]);
            }

            U *operator->() const noexcept {
                return creds_->get()[idx_];
            }

            iterator_t &operator++() {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                idx_++;
                BCRYPT_CODDING_ERROR_IF(idx_ == 0);
                return *this;
            }

            iterator_t operator++(int) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                iterator_t ret{idx_, creds_};
                idx_++;
                BCRYPT_CODDING_ERROR_IF(idx_ == 0);
                return ret;
            }

            iterator_t &operator+=(unsigned long offset) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                idx_ += offset;
                return *this;
            }

            iterator_t operator+(unsigned long offset) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                return iterator_t{idx_ + offset, creds_};
            }

            iterator_t &operator--() {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                BCRYPT_CODDING_ERROR_IF(idx_ == 0);
                idx_--;
                return *this;
            }

            iterator_t operator--(int) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                BCRYPT_CODDING_ERROR_IF(idx_ == 0);
                iterator_t ret{idx_, creds_};
                idx_--;
                return ret;
            }

            iterator_t &operator-=(unsigned long offset) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                idx_ -= offset;
                return *this;
            }

            iterator_t operator-(unsigned long offset) {
                BCRYPT_CODDING_ERROR_IF(creds_ == nullptr);
                return iterator_t{idx_ - offset, creds_};
            }

            bool operator==(iterator_t const &other) const {
                BCRYPT_CODDING_ERROR_IF_NOT(creds_ == other.creds_);
                return idx_ == other.idx_;
            }

            bool operator!=(iterator_t const &other) const {
                BCRYPT_CODDING_ERROR_IF_NOT(creds_ == other.creds_);
                return idx_ != other.idx_;
            }

        private:
            unsigned long idx_{0};
            cred_ptr<U *> *creds_{nullptr};
        };

        using iterator = iterator_t<T>;
        using const_iterator = iterator_t<T const>;

        [[nodiscard]] iterator begin() {
            return iterator{0, creds_};
        }

        [[nodiscard]] iterator end() {
            return iterator{size_, creds_};
        }

        [[nodiscard]] const_iterator cbegin() const {
            return const_iterator{0, const_cast<cred_ptr<T *> *>(&creds_), false};
        }

        [[nodiscard]] const_iterator cend() const {
            return const_iterator{size_, const_cast<cred_ptr<T *> *>(&creds_), false};
        }

        [[nodiscard]] iterator rbegin() {
            return iterator{size_ - 1, &creds_};
        }

        [[nodiscard]] iterator rend() {
            return iterator{0xFFFFFFFF, &creds_};
        }

        [[nodiscard]] const_iterator crbegin() {
            return const_iterator{size_ - 1, const_cast<cred_ptr<T *> *>(&creds_), false};
        }

        [[nodiscard]] const_iterator crend() {
            return const_iterator{0xFFFFFFFF, const_cast<cred_ptr<T *> *>(&creds_), false};
        }

    private:
        unsigned long size_{0};
        cred_ptr<T *> creds_;
    };

    template<typename T>
    void swap(cred_array<T> &lhs, cred_array<T> &rhs) {
        lhs.swap(rhs);
    }

    template<typename T>
    [[nodiscard]] unsigned long size(cred_array<T> &c) {
        return c.size();
    }

    template<typename T>
    [[nodiscard]] typename cred_array<T>::iterator begin(cred_array<T> &c) {
        return c.begin();
    }

    template<typename T>
    [[nodiscard]] typename cred_array<T>::iterator end(cred_array<T> &c) {
        return c.end();
    }

    template<typename T>
    [[nodiscard]] typename cred_array<T>::const_iterator cbegin(cred_array<T> const &c) {
        return c.cbegin();
    }

    template<typename T>
    [[nodiscard]] typename cred_array<T>::const_iterator cend(cred_array<T> const &c) {
        return c.cend();
    }

    using buffer_ptr = cred_ptr<char>;

    using buffer_cptr = cred_ptr<char const>;

    using credential_ptr = cred_ptr<CREDENTIALW>;

    using credentials_ptr = cred_ptr<CREDENTIALW *>;

    using credential_cptr = cred_ptr<CREDENTIALW const>;

    using credentials_cptr = cred_ptr<CREDENTIALW const *>;

    using credentials_array = cred_array<CREDENTIALW>;

    using credentials_carray = cred_array<CREDENTIALW const>;

    using target_info_ptr = cred_ptr<CREDENTIAL_TARGET_INFORMATIONW>;

    using target_info_cptr = cred_ptr<CREDENTIAL_TARGET_INFORMATIONW const>;

    using marshaled_credentials_ptr = cred_ptr<wchar_t>;

    using marshaled_credentials_cptr = cred_ptr<wchar_t const>;

    using packed_authenticated_buffer_ptr = cred_ptr<char>;

    using packed_authenticated_buffer_cptr = cred_ptr<char const>;

    template<typename T>
    struct target_info_traits;

    template<>
    struct target_info_traits<CREDENTIAL_TARGET_INFORMATIONA> {
        using character_type = char;
    };

    template<>
    struct target_info_traits<CREDENTIAL_TARGET_INFORMATIONW> {
        using character_type = wchar_t;
    };

    [[nodiscard]] inline std::error_code try_get_credentials(credentials_array *creds,
                                                             wchar_t const *filter = nullptr,
                                                             DWORD flags = 0) noexcept {
        DWORD count{0};
        CREDENTIALW **creds_tmp{nullptr};
        if (!CredEnumerateW(filter, flags, &count, &creds_tmp)) {
            return hcrypt::get_last_error_code();
        }
        creds->attach(count, creds_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline credentials_array get_credentials(wchar_t const *filter = nullptr,
                                                           DWORD flags = 0) {
        credentials_array creds;
        std::error_code err{try_get_credentials(&creds, filter, flags)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err, "CredEnumerateW failed");
        }
        return creds;
    }

    [[nodiscard]] inline std::error_code try_get_domain_credentials(
        CREDENTIAL_TARGET_INFORMATIONW const &target_info,
        DWORD flags,
        credentials_array *creds) noexcept {
        DWORD count{0};
        CREDENTIALW **creds_tmp{nullptr};
        if (!CredReadDomainCredentialsW(
                const_cast<CREDENTIAL_TARGET_INFORMATIONW *>(&target_info), flags, &count, &creds_tmp)) {
            return hcrypt::get_last_error_code();
        }
        creds->attach(count, creds_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline credentials_array get_domain_credentials(
        CREDENTIAL_TARGET_INFORMATIONW const &target_info, DWORD flags = 0) {
        credentials_array creds;
        std::error_code err{try_get_domain_credentials(target_info, flags, &creds)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS) &&
            err != hcrypt::make_win32_error_code(ERROR_NOT_FOUND)) {
            throw std::system_error(err, "CredEnumerateW failed");
        }
        return creds;
    }

    [[nodiscard]] inline std::error_code try_get_best_credentials(credential_ptr *creds,
                                                                  wchar_t const *target_name,
                                                                  DWORD type = 0) noexcept {
        CREDENTIALW *creds_tmp{nullptr};
        if (!CredFindBestCredentialW(target_name, type, 0, &creds_tmp)) {
            return hcrypt::get_last_error_code();
        }
        creds->attach(creds_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline credential_ptr get_best_credentials(wchar_t const *target_name,
                                                             DWORD type = 0) {
        credential_ptr creds;
        std::error_code err{try_get_best_credentials(&creds, target_name, type)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err, "CredFindBestCredentialW failed");
        }
        return creds;
    }

    [[nodiscard]] inline std::error_code try_get_target_info(target_info_ptr *creds,
                                                             wchar_t const *target_name,
                                                             DWORD flags = CRED_ALLOW_NAME_RESOLUTION) noexcept {
        CREDENTIAL_TARGET_INFORMATIONW *target_info_tmp{nullptr};
        if (!CredGetTargetInfoW(target_name, flags, &target_info_tmp)) {
            return hcrypt::get_last_error_code();
        }
        creds->attach(target_info_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline target_info_ptr get_target_info(wchar_t const *target_name,
                                                         DWORD flags = CRED_ALLOW_NAME_RESOLUTION) {
        target_info_ptr target_info;
        std::error_code err{try_get_target_info(&target_info, target_name, flags)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err, "CredGetTargetInfoW failed");
        }
        return target_info;
    }

    template<typename F, typename T>
    typename cred_array<T>::iterator find_first(cred_array<T> &creds,
                                                F const &f,
                                                DWORD flags = CRED_ENUMERATE_ALL_CREDENTIALS,
                                                wchar_t *filter = nullptr) {
        typename cred_array<T>::iterator cur{creds.begin()};
        typename cred_array<T>::iterator end{creds.end()};

        for (; cur != end; ++cur) {
            if (!f(*cur)) {
                break;
            }
        }

        return cur;
    }

    template<typename F, typename T>
    typename cred_array<T>::const_iterator find_first(cred_array<T> const &creds,
                                                      F const &f,
                                                      DWORD flags = CRED_ENUMERATE_ALL_CREDENTIALS,
                                                      wchar_t *filter = nullptr) {
        typename cred_array<T>::const_iterator cur{creds.cbegin()};
        typename cred_array<T>::const_iterator end{creds.cend()};

        for (; cur != end; ++cur) {
            if (!f(*cur)) {
                break;
            }
        }

        return cur;
    }

    template<typename F, typename T>
    inline void for_each(cred_array<T> &creds,
                         F const &f,
                         DWORD flags = CRED_ENUMERATE_ALL_CREDENTIALS,
                         wchar_t *filter = nullptr) {
        typename cred_array<T>::iterator cur{creds.begin()};
        typename cred_array<T>::iterator end{creds.end()};

        for (; cur != end; ++cur) {
            f(*cur);
        }
    }

    template<typename F, typename T>
    inline void for_each(cred_array<T> const &creds,
                         F const &f,
                         DWORD flags = CRED_ENUMERATE_ALL_CREDENTIALS,
                         wchar_t *filter = nullptr) {
        typename cred_array<T>::const_iterator cur{creds.cbegin()};
        typename cred_array<T>::const_iterator end{creds.cend()};

        for (; cur != end; ++cur) {
            f(*cur);
        }
    }

    using session_types_arr = std::array<DWORD, CRED_TYPE_MAXIMUM>;

    [[nodiscard]] inline std::error_code try_get_session_types(session_types_arr *arr) noexcept {
        if (!CredGetSessionTypes(static_cast<unsigned long>(arr->size()), arr->data())) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline session_types_arr get_session_types() {
        session_types_arr arr;
        if (!CredGetSessionTypes(static_cast<unsigned long>(arr.size()), arr.data())) {
            throw std::system_error(hcrypt::get_last_error_code());
        }
        return arr;
    }

    [[nodiscard]] inline bool is_marshaled_credential(wchar_t const *marshaled_credential) {
        return CredIsMarshaledCredentialW(marshaled_credential) ? true : false;
    }

    template<typename T>
    struct cred_type_to_marshal_type_t;

    template<>
    struct cred_type_to_marshal_type_t<CERT_CREDENTIAL_INFO> {
        constexpr static CRED_MARSHAL_TYPE value{CertCredential};
    };

    template<>
    struct cred_type_to_marshal_type_t<USERNAME_TARGET_CREDENTIAL_INFO> {
        constexpr static CRED_MARSHAL_TYPE value{UsernameTargetCredential};
    };

    template<>
    struct cred_type_to_marshal_type_t<BINARY_BLOB_CREDENTIAL_INFO> {
        constexpr static CRED_MARSHAL_TYPE value{BinaryBlobCredential};
    };

    template<typename T>
    [[nodiscard]] inline std::error_code try_marshal_credential(
        T &credentials, marshaled_credentials_ptr *marshaled_credentials) noexcept {
        wchar_t *marshaled_credentials_tmp{nullptr};
        if (!CredMarshalCredentialW(cred_type_to_marshal_type_t<T>::value,
                                    static_cast<void *>(&credentials),
                                    &marshaled_credentials_tmp)) {
            return hcrypt::get_last_error_code();
        }
        marshaled_credentials->attach(marshaled_credentials_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    template<typename T>
    [[nodiscard]] inline marshaled_credentials_ptr marshal_credential(T &credentials) {
        marshaled_credentials_ptr marshaled_credentials;
        std::error_code err{try_marshal_credential(credentials, &marshaled_credentials)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
        return marshaled_credentials;
    }

    [[nodiscard]] inline std::error_code try_unmarshal_credential(wchar_t const *marshaled_credentials,
                                                                  CRED_MARSHAL_TYPE *credentials_type,
                                                                  buffer_ptr *buffer) {
        void *buffer_tmp{nullptr};
        if (!CredUnmarshalCredentialW(marshaled_credentials, credentials_type, &buffer_tmp)) {
            return hcrypt::make_win32_error_code(ERROR_SUCCESS);
        }
        buffer->attach(reinterpret_cast<char *>(buffer_tmp));
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    struct unmarshaled_credentials {
        unmarshaled_credentials() = default;
        ~unmarshaled_credentials() = default;

        unmarshaled_credentials(unmarshaled_credentials &&) = default;
        unmarshaled_credentials &operator=(unmarshaled_credentials &&) = default;

        unmarshaled_credentials(unmarshaled_credentials const &) = delete;
        unmarshaled_credentials &operator=(unmarshaled_credentials const &) = delete;

        CRED_MARSHAL_TYPE type{static_cast<CRED_MARSHAL_TYPE>(0)};
        buffer_ptr buffer;
    };

    [[nodiscard]] inline unmarshaled_credentials unmarshal_credentials(wchar_t const *marshaled_credentials) {
        unmarshaled_credentials creds;
        std::error_code err{try_unmarshal_credential(
            marshaled_credentials, &creds.type, &creds.buffer)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
        return creds;
    }

    [[nodiscard]] inline std::error_code try_pack_authentication_buffer(
        DWORD flags,
        wchar_t const *user_name,
        wchar_t const *password,
        char *packed_authenticated_buffer,
        DWORD *size) noexcept {
        if (!CredPackAuthenticationBufferW(flags,
                                           const_cast<wchar_t *>(user_name),
                                           const_cast<wchar_t *>(password),
                                           reinterpret_cast<PBYTE>(packed_authenticated_buffer),
                                           size)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline hcrypt::buffer pack_authentication_buffer(
        DWORD flags, wchar_t const *user_name, wchar_t const *password) {
        DWORD size{0};
        std::error_code err{try_pack_authentication_buffer(
            flags, user_name, password, nullptr, &size)};
        if (err != hcrypt::make_win32_error_code(ERROR_INSUFFICIENT_BUFFER)) {
            throw std::system_error(err);
        }
        BCRYPT_CODDING_ERROR_IF(0 == size);
        hcrypt::buffer packed_authenticated_buffer;
        packed_authenticated_buffer.resize(size);
        DWORD size2{size};
        err = try_pack_authentication_buffer(
            flags, user_name, password, packed_authenticated_buffer.data(), &size2);
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
        BCRYPT_CODDING_ERROR_IF_NOT(size == size2);
        return packed_authenticated_buffer;
    }

    [[nodiscard]] inline std::error_code try_protect(bool as_self,
                                                     wchar_t const *credentials,
                                                     size_t credentials_size,
                                                     wchar_t *protected_credentials,
                                                     size_t *protected_credentials_size,
                                                     CRED_PROTECTION_TYPE *protection_type = nullptr) noexcept {
        CRED_PROTECTION_TYPE protection_type_tmp{CredUnprotected};
        DWORD protected_credentials_size_tmp{static_cast<DWORD>(*protected_credentials_size)};
        if (!CredProtectW(as_self ? TRUE : FALSE,
                          const_cast<wchar_t *>(credentials),
                          static_cast<DWORD>(credentials_size),
                          protected_credentials,
                          &protected_credentials_size_tmp,
                          &protection_type_tmp)) {
            DWORD err{GetLastError()};
            BCRYPT_CODDING_ERROR_IF(err == ERROR_SUCCESS);
            *protected_credentials_size = protected_credentials_size_tmp;
            return hcrypt::make_win32_error_code(err);
        }
        *protected_credentials_size = protected_credentials_size_tmp;
        if (protection_type) {
            *protection_type = protection_type_tmp;
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline std::error_code try_get_protectection_type(
        wchar_t const *protected_credentials, CRED_PROTECTION_TYPE *protection_type) noexcept {
        if (!CredIsProtectedW(const_cast<wchar_t *>(protected_credentials), protection_type)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline CRED_PROTECTION_TYPE get_protectection_type(wchar_t const *protected_credentials) {
        CRED_PROTECTION_TYPE protection_type{CredUnprotected};
        if (!CredIsProtectedW(const_cast<wchar_t *>(protected_credentials), &protection_type)) {
            throw std::system_error(hcrypt::get_last_error_code());
        }
        return protection_type;
    }

    [[nodiscard]] inline std::pmr::wstring protect(bool as_self,
                                                   wchar_t const *credentials,
                                                   size_t credentials_size,
                                                   CRED_PROTECTION_TYPE *protection_type = nullptr) {
        std::pmr::wstring protected_credentials{hcrypt::get_secure_memory_resource()};
        size_t size{0};

        for (;;) {
            std::error_code err{try_protect(as_self,
                                            credentials,
                                            credentials_size,
                                            size ? protected_credentials.data() : nullptr,
                                            &size,
                                            protection_type)};
            protected_credentials.resize(size);
            if (err == hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
                break;
            } else if (err != hcrypt::make_win32_error_code(ERROR_INSUFFICIENT_BUFFER)) {
                throw std::system_error(err);
            }
            BCRYPT_CODDING_ERROR_IF(0 == size);
        }
        return protected_credentials;
    }

    [[nodiscard]] inline std::error_code try_unprotect(bool as_self,
                                                       wchar_t const *protected_credentials,
                                                       size_t protected_credentials_size,
                                                       wchar_t *credentials,
                                                       size_t *credentials_size) noexcept {
        DWORD credentials_size_tmp{static_cast<DWORD>(*credentials_size)};
        if (!CredUnprotectW(as_self ? TRUE : FALSE,
                            const_cast<wchar_t *>(protected_credentials),
                            static_cast<DWORD>(protected_credentials_size),
                            credentials,
                            &credentials_size_tmp)) {
            DWORD err{GetLastError()};
            BCRYPT_CODDING_ERROR_IF(err == ERROR_SUCCESS);
            *credentials_size = credentials_size_tmp;
            return hcrypt::make_win32_error_code(err);
        }
        *credentials_size = credentials_size_tmp;
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline std::pmr::wstring unprotect(bool as_self,
                                                     wchar_t const *protected_credentials,
                                                     size_t protected_credentials_size) {
        std::pmr::wstring credentials{hcrypt::get_secure_memory_resource()};
        size_t size{0};

        for (;;) {
            std::error_code err{try_unprotect(as_self,
                                              protected_credentials,
                                              protected_credentials_size,
                                              size ? credentials.data() : nullptr,
                                              &size)};
            credentials.resize(size);
            if (err == hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
                break;
            } else if (err != hcrypt::make_win32_error_code(ERROR_INSUFFICIENT_BUFFER)) {
                throw std::system_error(err);
            }
            BCRYPT_CODDING_ERROR_IF(0 == size);
        }
        return credentials;
    }

    [[nodiscard]] inline std::error_code try_rename(DWORD credentials_type,
                                                    wchar_t const *old_target_name,
                                                    wchar_t const *new_target_name) noexcept {
        //
        // This API is not supported and always returns ERROR_NOT_SUPPORTED
        //
        if (!CredRenameW(old_target_name, new_target_name, credentials_type, 0)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    void rename(DWORD credentials_type, wchar_t const *old_target_name, wchar_t const *new_target_name) {
        std::error_code err{try_rename(credentials_type, old_target_name, new_target_name)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
    }

    [[nodiscard]] inline std::error_code try_read_credentials(wchar_t const *target_name,
                                                              DWORD type,
                                                              credential_ptr *credentials) {
        CREDENTIALW *credentials_tmp{nullptr};
        if (!CredReadW(target_name, type, 0, &credentials_tmp)) {
            return hcrypt::get_last_error_code();
        }
        credentials->attach(credentials_tmp);
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    [[nodiscard]] inline credential_ptr read_credentials(wchar_t const *target_name,
                                                         DWORD type) {
        credential_ptr credentials_tmp;
        std::error_code err{try_read_credentials(target_name, type, &credentials_tmp)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS) &&
            err != hcrypt::make_win32_error_code(ERROR_NOT_FOUND)) {
            throw std::system_error(err);
        }
        return credentials_tmp;
    }

    [[nodiscard]] inline std::error_code try_write_credentials(CREDENTIALW *credentials,
                                                               DWORD flags = 0) {
        if (!CredWriteW(credentials, flags)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    inline void write_credentials(CREDENTIALW *credentials, DWORD flags = 0) {
        std::error_code err{try_write_credentials(credentials, flags)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
    }

    [[nodiscard]] inline std::error_code try_delete_credentials(wchar_t const *target_name,
                                                                DWORD credentials_type) {
        if (!CredDeleteW(target_name, credentials_type, 0)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    inline void delete_credentials(wchar_t const *target_name, DWORD credentials_type) {
        std::error_code err{try_delete_credentials(target_name, credentials_type)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
    }

    [[nodiscard]] inline std::error_code try_write_domain_credentials(
        PCREDENTIAL_TARGET_INFORMATIONW target_info, CREDENTIALW *credentials, DWORD flags = 0) {
        if (!CredWriteDomainCredentialsW(target_info, credentials, flags)) {
            return hcrypt::get_last_error_code();
        }
        return hcrypt::make_win32_error_code(ERROR_SUCCESS);
    }

    inline void write_domain_credentials(PCREDENTIAL_TARGET_INFORMATIONW target_info,
                                         CREDENTIALW *credentials,
                                         DWORD flags = 0) {
        std::error_code err{try_write_domain_credentials(target_info, credentials, flags)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
    }

    [[nodiscard]] inline std::error_code try_store_sso_cred(wchar_t const *realm,
                                                            wchar_t const *user_name,
                                                            wchar_t const *password,
                                                            bool persist = false) {
        return hcrypt::make_win32_error_code(CredUIStoreSSOCredW(
            realm, user_name, password, persist ? TRUE : FALSE));
    }

    inline void store_sso_cred(wchar_t const *realm,
                               wchar_t const *user_name,
                               wchar_t const *password,
                               bool persist = false) {
        std::error_code err{try_store_sso_cred(realm, user_name, password, persist)};
        if (err != hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
            throw std::system_error(err);
        }
    }

    struct user_name_password {
        std::wstring name;
        std::pmr::wstring password{hcrypt::get_secure_memory_resource()};
    };

    [[nodiscard]] inline user_name_password cmd_promp_for_credentials(
        wchar_t const *target_name,
        wchar_t const *user_name,
        wchar_t const *password,
        bool *save_credentials,
        DWORD flags = 0,
        DWORD authentication_error = ERROR_SUCCESS) {
        std::vector<wchar_t> user_name_buffer;
        user_name_buffer.reserve(CREDUI_MAX_USERNAME_LENGTH + 1);
        wcsncpy_s(user_name_buffer.data(), user_name_buffer.size(), user_name, _TRUNCATE);

        std::pmr::vector<wchar_t> password_buffer{hcrypt::get_secure_memory_resource()};
        password_buffer.reserve(CREDUI_MAX_PASSWORD_LENGTH + 1);
        wcsncpy_s(password_buffer.data(), password_buffer.size(), password, _TRUNCATE);

        ULONG new_user_name_length{static_cast<ULONG>(user_name_buffer.size())};
        ULONG new_password_length{static_cast<ULONG>(password_buffer.size())};

        BOOL save_credentials_tmp{save_credentials ? (*save_credentials ? TRUE : FALSE) : FALSE};

        if (!CredUICmdLinePromptForCredentialsW(target_name,
                                                nullptr,
                                                authentication_error,
                                                user_name_buffer.data(),
                                                new_user_name_length,
                                                password_buffer.data(),
                                                new_password_length,
                                                save_credentials ? &save_credentials_tmp : nullptr,
                                                flags)) {
            throw std::system_error(hcrypt::get_last_error_code());
        }

        user_name_buffer[user_name_buffer.size() - 1] = L'\0';
        password_buffer[password_buffer.size() - 1] = L'\0';

        if (save_credentials) {
            *save_credentials = save_credentials_tmp;
        }

        user_name_password result;

        result.name.assign(user_name_buffer.data());
        result.password.assign(password_buffer.data());

        return result;
    }

    struct user_name_domain {
        std::wstring name;
        std::wstring domain;
    };

    [[nodiscard]] inline user_name_domain parse_user_name(wchar_t const *user_name) {
        std::vector<wchar_t> user_name_buffer;
        user_name_buffer.reserve(CREDUI_MAX_USERNAME_LENGTH + 1);

        std::vector<wchar_t> domain_buffer;
        domain_buffer.reserve(CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1);

        ULONG new_user_name_length{static_cast<ULONG>(user_name_buffer.size())};
        ULONG new_domain_length{static_cast<ULONG>(domain_buffer.size())};

        DWORD err{CredUIParseUserNameW(user_name,
                                       user_name_buffer.data(),
                                       new_user_name_length,
                                       domain_buffer.data(),
                                       new_domain_length)};

        if (err != ERROR_SUCCESS) {
            throw std::system_error(hcrypt::make_win32_error_code(err));
        }

        user_name_buffer[user_name_buffer.size() - 1] = L'\0';
        domain_buffer[domain_buffer.size() - 1] = L'\0';

        user_name_domain result;

        result.name.assign(user_name_buffer.data());
        result.domain.assign(domain_buffer.data());

        return result;
    }

    inline std::wstring credential_flags_to_string(unsigned long flags) {
        std::wstring str;
        if (hcrypt::consume_flag(&flags, static_cast<unsigned long>(CRED_FLAGS_PROMPT_NOW))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_FLAGS_PROMPT_NOW");
        }
        if (hcrypt::consume_flag(&flags, static_cast<unsigned long>(CRYPT_LOCAL))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_FLAGS_USERNAME_TARGET");
        }
        if (flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", flags).c_str());
        }
        return str;
    }

    inline std::wstring target_info_flags_to_string(unsigned long flags) {
        std::wstring str;
        if (hcrypt::consume_flag(
                &flags, static_cast<unsigned long>(CRED_TI_SERVER_FORMAT_UNKNOWN))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_SERVER_FORMAT_UNKNOWN");
        }
        if (hcrypt::consume_flag(
                &flags, static_cast<unsigned long>(CRED_TI_DOMAIN_FORMAT_UNKNOWN))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_DOMAIN_FORMAT_UNKNOWN");
        }
        if (hcrypt::consume_flag(
                &flags, static_cast<unsigned long>(CRED_TI_ONLY_PASSWORD_REQUIRED))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_ONLY_PASSWORD_REQUIRED");
        }
        if (hcrypt::consume_flag(&flags, static_cast<unsigned long>(CRED_TI_USERNAME_TARGET))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_USERNAME_TARGET");
        }
        if (hcrypt::consume_flag(
                &flags, static_cast<unsigned long>(CRED_TI_CREATE_EXPLICIT_CRED))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_CREATE_EXPLICIT_CRED");
        }
        if (hcrypt::consume_flag(&flags, static_cast<unsigned long>(CRED_TI_WORKGROUP_MEMBER))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_WORKGROUP_MEMBER");
        }
        if (hcrypt::consume_flag(
                &flags, static_cast<unsigned long>(CRED_TI_DNSTREE_IS_DFS_SERVER))) {
            hcrypt::append_with_separator(&str, L" | ", L"CRED_TI_DNSTREE_IS_DFS_SERVER");
        }

        if (flags) {
            hcrypt::append_with_separator(
                &str, L" | ", hcrypt::make_wstring(L"0x%lx", flags).c_str());
        }
        return str;
    }

    constexpr inline wchar_t const *protection_type_to_string(CRED_PROTECTION_TYPE val) {
        wchar_t const *str{L"unknown protection type"};
        switch (val) {
        case CredUnprotected:
            str = L"CredUnprotected";
            break;
        case CredUserProtection:
            str = L"CredUserProtection";
            break;
        case CredTrustedProtection:
            str = L"CredTrustedProtection";
            break;
        case CredForSystemProtection:
            str = L"CredForSystemProtection";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const *marshal_type_to_string(CRED_MARSHAL_TYPE val) {
        wchar_t const *str{L"unknown marshal type"};
        switch (val) {
        case CertCredential:
            str = L"CertCredential";
            break;
        case UsernameTargetCredential:
            str = L"UsernameTargetCredential";
            break;
        case BinaryBlobCredential:
            str = L"BinaryBlobCredential";
            break;
        case UsernameForPackedCredentials:
            str = L"UsernameForPackedCredentials";
            break;
        case BinaryBlobForSystem:
            str = L"BinaryBlobForSystem";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const *credential_type_to_string(unsigned long val) {
        wchar_t const *str{L"unknown credentials type"};
        switch (val) {
        case CRED_TYPE_GENERIC:
            str = L"CRED_TYPE_GENERIC";
            break;
        case CRED_TYPE_DOMAIN_PASSWORD:
            str = L"CRED_TYPE_DOMAIN_PASSWORD";
            break;
        case CRED_TYPE_DOMAIN_CERTIFICATE:
            str = L"CRED_TYPE_DOMAIN_CERTIFICATE";
            break;
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
            str = L"CRED_TYPE_DOMAIN_VISIBLE_PASSWORD";
            break;
        case CRED_TYPE_GENERIC_CERTIFICATE:
            str = L"CRED_TYPE_GENERIC_CERTIFICATE";
            break;
        case CRED_TYPE_DOMAIN_EXTENDED:
            str = L"CRED_TYPE_DOMAIN_EXTENDED";
            break;
        case CRED_TYPE_MAXIMUM:
            str = L"CRED_TYPE_MAXIMUM";
            break;
        case CRED_TYPE_MAXIMUM_EX:
            str = L"CRED_TYPE_MAXIMUM_EX";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const *credential_persist_type_to_string(unsigned long val) {
        wchar_t const *str{L"unknown persist type"};
        switch (val) {
        case CRED_TYPE_GENERIC:
            str = L"CRED_PERSIST_SESSION";
            break;
        case CRED_PERSIST_LOCAL_MACHINE:
            str = L"CRED_PERSIST_LOCAL_MACHINE";
            break;
        case CRED_PERSIST_ENTERPRISE:
            str = L"CRED_PERSIST_ENTERPRISE";
            break;
        }
        return str;
    }

    constexpr inline wchar_t const *credential_session_persist_type_to_string(unsigned long val) {
        wchar_t const *str{L"unknown session persist type"};
        switch (val) {
        case CRED_PERSIST_NONE:
            str = L"CRED_PERSIST_NONE";
            break;
        case CRED_PERSIST_SESSION:
            str = L"CRED_PERSIST_SESSION";
            break;
        case CRED_PERSIST_LOCAL_MACHINE:
            str = L"CRED_PERSIST_LOCAL_MACHINE";
            break;
        case CRED_PERSIST_ENTERPRISE:
            str = L"CRED_PERSIST_ENTERPRISE";
            break;
        }
        return str;
    }

} // namespace credman