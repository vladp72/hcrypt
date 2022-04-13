#pragma once

#include "hcrypt_common.hpp"

#include <wincred.h>

#pragma comment(lib, "Credui.lib")

namespace credman {

    std::pmr::vector<char> ui_prompt_for_credentials(ULONG *auth_package,
                                                     void *auth_buffer,
                                                     ULONG auth_buffer_size,
                                                     PCREDUI_INFOW ui_info = nullptr,
                                                     bool *save_credentials = nullptr,
                                                     DWORD flags = 0,
                                                     DWORD auth_error = ERROR_SUCCESS) {
        void *out_auth_buffer{nullptr};
        ULONG out_auth_buffer_size{0};

        BOOL save_credentials_tmp{save_credentials ? (*save_credentials ? TRUE : FALSE) : FALSE};

        auto scoped_free_out_buffer{hcrypt::make_scope_guard([&out_auth_buffer, &out_auth_buffer_size] {
            if (out_auth_buffer) {
                SecureZeroMemory(out_auth_buffer, out_auth_buffer_size);
                CoTaskMemFree(out_auth_buffer);
            }
        })};

        DWORD err{CredUIPromptForWindowsCredentialsW(ui_info,
                                                     auth_error,
                                                     auth_package,
                                                     auth_buffer,
                                                     auth_buffer_size,
                                                     &out_auth_buffer,
                                                     &out_auth_buffer_size,
                                                     save_credentials ? &save_credentials_tmp : nullptr,
                                                     flags)};
        if (err != ERROR_SUCCESS) {
            throw std::system_error(hcrypt::make_win32_error_code(err));
        }

        std::pmr::vector<char> result{hcrypt::get_secure_memory_resource()};
        result.resize(out_auth_buffer_size);
        memcpy(result.data(), out_auth_buffer, out_auth_buffer_size);

        if (save_credentials) {
            *save_credentials = save_credentials_tmp;
        }

        return result;
    }

    [[nodiscard]] inline std::error_code try_confirm_credentials(wchar_t const *target_name,
                                                                 bool confirm) {
        DWORD err{CredUIConfirmCredentialsW(target_name, confirm ? TRUE : FALSE)};
        return hcrypt::make_win32_error_code(err);
    }

    void confirm_credentials(wchar_t const *target_name, bool confirm) {
        std::error_code err{try_confirm_credentials(target_name, confirm)};
        if (err != hcrypt::make_win32_error_code(NO_ERROR)) {
            throw std::system_error(err);
        }
    }

    [[nodiscard]] inline std::error_code try_unpack_authentication_buffer(
        DWORD flags,
        void const *buffer,
        size_t buffer_size,
        wchar_t *user_name,
        size_t *user_name_size,
        wchar_t *domain_name,
        size_t *domain_name_size,
        wchar_t *password,
        size_t *password_size) noexcept {
        DWORD user_name_size_tmp{user_name_size ? static_cast<DWORD>(*user_name_size) : 0};
        DWORD domain_name_size_tmp{
            domain_name_size ? static_cast<DWORD>(*domain_name_size) : 0};
        DWORD password_size_tmp{password_size ? static_cast<DWORD>(*password_size) : 0};

        DWORD err{ERROR_SUCCESS};

        if (!CredUnPackAuthenticationBufferW(flags,
                                             const_cast<void *>(buffer),
                                             static_cast<DWORD>(buffer_size),
                                             user_name,
                                             &user_name_size_tmp,
                                             domain_name,
                                             &domain_name_size_tmp,
                                             password,
                                             &password_size_tmp)) {
            err = GetLastError();
        }

        if (user_name_size) {
            *user_name_size = user_name_size_tmp;
        }
        if (domain_name_size) {
            *domain_name_size = domain_name_size_tmp;
        }
        if (password_size) {
            *password_size = password_size_tmp;
        }

        return hcrypt::make_win32_error_code(err);
    }

    struct unpacked_credentials {
        std::wstring user_name;
        std::wstring domain_name;
        std::pmr::wstring password{hcrypt::get_secure_memory_resource()};
    };

    [[nodiscard]] inline unpacked_credentials unpack_authentication_buffer(
        DWORD flags, void const *buffer, size_t buffer_size) {
        unpacked_credentials result;

        size_t user_name_size{0};
        size_t domain_name_size{0};
        size_t password_size{0};

        std::error_code err{try_unpack_authentication_buffer(
            flags, buffer, buffer_size, nullptr, &user_name_size, nullptr, &domain_name_size, nullptr, &password_size)};

        if (err == hcrypt::make_win32_error_code(ERROR_INSUFFICIENT_BUFFER)) {
            result.user_name.resize(user_name_size);
            result.domain_name.resize(domain_name_size);
            result.password.resize(password_size);

            size_t user_name_size2{user_name_size};
            size_t domain_name_size2{domain_name_size};
            size_t password_size2{password_size};

            err = try_unpack_authentication_buffer(flags,
                                                   buffer,
                                                   buffer_size,
                                                   result.user_name.data(),
                                                   &user_name_size2,
                                                   result.domain_name.data(),
                                                   &domain_name_size2,
                                                   result.password.data(),
                                                   &password_size2);

            if (err == hcrypt::make_win32_error_code(ERROR_SUCCESS)) {
                BCRYPT_CODDING_ERROR_IF_NOT(user_name_size == user_name_size2);
                BCRYPT_CODDING_ERROR_IF_NOT(domain_name_size == domain_name_size2);
                BCRYPT_CODDING_ERROR_IF_NOT(password_size == password_size2);

                return result;
            }
        }

        throw std::system_error(err);
    }
} // namespace credman