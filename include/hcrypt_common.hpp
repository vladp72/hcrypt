#pragma once

#include <utility>
#include <type_traits>
#include <system_error>
#include <vector>
#include <string>
#include <string_view>
#include <chrono>

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")

#define BCRYPT_PLATFORM_FAIL_FAST(EC) \
    {                                 \
        __debugbreak();               \
        __fastfail(EC);               \
    }

#ifndef BCRYPT_FAST_FAIL
#define BCRYPT_FAST_FAIL(EC) \
    { BCRYPT_PLATFORM_FAIL_FAST(EC); }
#endif

#ifndef BCRYPT_CRASH_APPLICATION
#define BCRYPT_CRASH_APPLICATION() BCRYPT_FAST_FAIL(ENOTRECOVERABLE)
#endif

#ifndef BCRYPT_CODDING_ERROR_IF
#define BCRYPT_CODDING_ERROR_IF(C)         \
    if (C) {                               \
        BCRYPT_FAST_FAIL(ENOTRECOVERABLE); \
    } else {                               \
        ;                                  \
    }
#endif

#ifndef BCRYPT_CODDING_ERROR_IF_NOT
#define BCRYPT_CODDING_ERROR_IF_NOT(C)     \
    if (C) {                               \
        ;                                  \
    } else {                               \
        BCRYPT_FAST_FAIL(ENOTRECOVERABLE); \
    }
#endif

#ifndef BCRYPT_DBG_CODDING_ERROR_IF_NOT
#define BCRYPT_DBG_CODDING_ERROR_IF_NOT(C) BCRYPT_CODDING_ERROR_IF_NOT(C)
#endif

#ifndef BCRYPT_DBG_CODDING_ERROR_IF
#define BCRYPT_DBG_CODDING_ERROR_IF(C) BCRYPT_CODDING_ERROR_IF(C)
#endif

namespace hcrypt {

    inline void erase_tail_zeroes(std::string &str) {
        if (str.empty()) {
            return;
        }

        size_t idx{str.size() - 1};
        size_t count{0};

        while (0 != idx && '\0' == str[idx]) {
            --idx;
            ++count;
        }

        if (count) {
            str.erase(idx, count);
        }
    }

    inline void erase_tail_zeroes(std::wstring &str) {
        if (str.empty()) {
            return;
        }

        size_t idx{str.size() - 1};
        size_t count{0};

        while (0 != idx && L'\0' == str[idx]) {
            --idx;
            ++count;
        }

        if (count) {
            str.erase(idx, count);
        }
    }

    inline std::string v_make_string(char const *format, va_list argptr) {
        size_t buffer_size = _vscprintf(format, argptr);

        int err{0};

        if (-1 == buffer_size) {
            err = errno;
            throw std::system_error{
                err, std::generic_category(), "_vscprintf failed, invalid formatting string passed to v_make_string"};
        }

        std::string str;

        if (0 == buffer_size) {
            return str;
        }

        str.resize(buffer_size + 1);

        _vsnprintf_s(&str[0], str.size(), _TRUNCATE, format, argptr);

        if (-1 == buffer_size) {
            err = errno;
            throw std::system_error{
                err, std::generic_category(), "_vsnprintf_s failed, invalid formatting string passed to v_make_string"};
        }

        erase_tail_zeroes(str);

        return str;
    }

    inline std::string make_string(char const *format, ...) {
        va_list argptr;
        va_start(argptr, format);
        return v_make_string(format, argptr);
    }

    inline std::wstring v_make_wstring(wchar_t const *format, va_list argptr) {
        size_t buffer_size = _vscwprintf(format, argptr);

        int err{0};

        if (-1 == buffer_size) {
            err = errno;
            throw std::system_error{
                err, std::generic_category(), "_vscwprintf failed, invalid formatting string passed to v_make_wstring"};
        }

        std::wstring str;

        if (0 == buffer_size) {
            return str;
        }

        str.resize(buffer_size + 1, 0);

        _vsnwprintf_s(&str[0], str.size(), _TRUNCATE, format, argptr);

        if (-1 == buffer_size) {
            err = errno;
            throw std::system_error{
                err, std::generic_category(), "_vsnwprintf_s failed, invalid formatting string passed to v_make_wstring"};
        }

        erase_tail_zeroes(str);

        return str;
    }

    inline std::wstring make_wstring(wchar_t const *format, ...) {
        va_list argptr;
        va_start(argptr, format);
        return v_make_wstring(format, argptr);
    }

    inline std::wstring a_to_u(char const *in_str, UINT codepage = CP_ACP, DWORD flags = 0) {
        DWORD err{ERROR_SUCCESS};
        std::wstring out_str;

        int size{::MultiByteToWideChar(codepage, flags, in_str, -1, nullptr, 0)};

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                throw std::system_error{
                    static_cast<int>(err),
                    std::system_category(),
                    "MultiByteToWideChar failed while estimating size"};
            }
            return out_str;
        }

        out_str.resize(size);

        size = ::MultiByteToWideChar(codepage, flags, in_str, -1, &out_str[0], size);

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                throw std::system_error{
                    static_cast<int>(err),
                    std::system_category(),
                    "MultiByteToWideChar failed while estimating size"};
            }
        }

        erase_tail_zeroes(out_str);

        return out_str;
    }

    inline std::wstring a_to_u(std::string const &in_str, UINT codepage = CP_ACP, DWORD flags = 0) {
        return a_to_u(in_str.c_str(), codepage, flags);
    }

    inline std::string u_to_a(wchar_t const *in_str,
                              UINT codepage = CP_ACP,
                              DWORD flags = 0,
                              char const *default_char = nullptr,
                              bool *is_default_used = nullptr) {
        DWORD err{ERROR_SUCCESS};
        std::string out_str;
        BOOL is_default_used_tmp = FALSE;

        int size{::WideCharToMultiByte(codepage, flags, in_str, -1, NULL, 0, nullptr, nullptr)};

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                throw std::system_error{
                    static_cast<int>(err),
                    std::system_category(),
                    "WideCharToMultiByte failed while estimating size"};
            }
            return out_str;
        }

        out_str.resize(size);

        size = ::WideCharToMultiByte(
            codepage, flags, in_str, -1, &out_str[0], size, default_char, &is_default_used_tmp);

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                throw std::system_error{
                    static_cast<int>(err),
                    std::system_category(),
                    "WideCharToMultiByte failed while estimating size"};
            }
        }

        erase_tail_zeroes(out_str);

        if (is_default_used) {
            *is_default_used = is_default_used_tmp ? true : false;
        }

        return out_str;
    }

    inline std::string u_to_a(std::wstring const &in_str,
                              UINT codepage = CP_ACP,
                              DWORD flags = 0,
                              char const *default_char = nullptr,
                              bool *is_default_used = nullptr) {
        return u_to_a(in_str.c_str(), codepage, flags, default_char, is_default_used);
    }

    enum class status : long {
        success = 0L,                                     // STATUS_SUCCESS
        no_more_entries = static_cast<long>(0x8000001AL), // STATUS_NO_MORE_ENTRIES
        unsuccessful = static_cast<long>(0xC0000001L),    // STATUS_UNSUCCESSFUL
        invalid_handle = static_cast<long>(0xC0000008L), // STATUS_INVALID_HANDLE
        no_memory = static_cast<long>(0xC0000017L),      // STATUS_NO_MEMORY
        buffer_too_small = static_cast<long>(0xC0000023L), // STATUS_BUFFER_TOO_SMALL
        object_name_not_found = static_cast<long>(0xC0000034L), // STATUS_OBJECT_NAME_NOT_FOUND
        insufficient_resources = static_cast<long>(0xC000009AL), // STATUS_INSUFFICIENT_RESOURCES
        invalid_parameter = static_cast<long>(0xC000000DL), // STATUS_INVALID_PARAMETER
        internal_error = static_cast<long>(0xC00000E5L), // STATUS_INTERNAL_ERROR
        invalid_buffer_size = static_cast<long>(0xC0000206L), // STATUS_INVALID_BUFFER_SIZE
        not_found = static_cast<long>(0xC0000225L),     // STATUS_NOT_FOUND
        not_supported = static_cast<long>(0xC00000BBL), // STATUS_NOT_SUPPORTED
        invalid_signature = static_cast<long>(0xC000A000L), // STATUS_INVALID_SIGNATURE
        auth_tag_mismatch = static_cast<long>(0xC000A002L), // STATUS_AUTH_TAG_MISMATCH
    };

    constexpr inline bool is_success(status const s) {
        return s >= status::success;
    }

    constexpr inline bool is_failure(status const s) {
        return !is_success(s);
    }

    constexpr inline bool is_success(long const s) {
        return is_success(static_cast<status const>(s));
    }

    constexpr inline bool is_failure(long const s) {
        return is_failure(static_cast<status const>(s));
    }

    constexpr inline bool is_success(int const s) {
        return is_success(static_cast<status const>(s));
    }

    constexpr inline bool is_failure(int const s) {
        return is_failure(static_cast<status const>(s));
    }

    constexpr inline char const *try_status_to_string(status const status) {
        char const *str{nullptr};
        switch (status) {
        case status::success:
            str = "success";
            break;
        case status::no_more_entries:
            str = "no_more_entries";
            break;
        case status::buffer_too_small:
            str = "buffer_too_small";
            break;
        case status::insufficient_resources:
            str = "insufficient_resources";
            break;
        case status::invalid_signature:
            str = "invalid_signature";
            break;
        case status::auth_tag_mismatch:
            str = "auth_tag_mismatch";
            break;
        case status::unsuccessful:
            str = "unsuccessful";
            break;
        case status::not_found:
            str = "not_found";
            break;
        case status::object_name_not_found:
            str = "object_name_not_found";
            break;
        case status::invalid_parameter:
            str = "invalid_parameter";
            break;
        case status::internal_error:
            str = "internal_error";
            break;
        case status::no_memory:
            str = "no_memory";
            break;
        case status::invalid_buffer_size:
            str = "invalid_buffer_size";
            break;
        case status::invalid_handle:
            str = "invalid_handle";
            break;
        case status::not_supported:
            str = "not_supported";
            break;
        }
        return str;
    }

    constexpr inline char const *status_to_string(status const status) {
        char const *str{try_status_to_string(status)};
        if (nullptr == str) {
            str = "unknown status";
        }
        return str;
    }

    constexpr inline char const *status_to_string(int const s) {
        return status_to_string(static_cast<status>(s));
    }

    constexpr inline DWORD status_to_win32_error(status const status) {
        DWORD win32_error{static_cast<DWORD>(status)};
        switch (status) {
        case status::success:
            win32_error = ERROR_SUCCESS;
            break;
        case status::buffer_too_small:
            win32_error = ERROR_INSUFFICIENT_BUFFER;
            break;
        case status::insufficient_resources:
            win32_error = ERROR_NO_SYSTEM_RESOURCES;
            break;
        case status::invalid_signature:
            win32_error = NTE_BAD_SIGNATURE;
            break;
        case status::auth_tag_mismatch:
            win32_error = ERROR_CRC;
            break;
        case status::unsuccessful:
            win32_error = ERROR_GEN_FAILURE;
            break;
        case status::not_found:
            win32_error = ERROR_NOT_FOUND;
            break;
        case status::object_name_not_found:
            win32_error = ERROR_FILE_NOT_FOUND;
            break;
        case status::invalid_parameter:
            win32_error = ERROR_INVALID_PARAMETER;
            break;
        case status::internal_error:
            win32_error = ERROR_INTERNAL_ERROR;
            break;
        case status::no_memory:
            win32_error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        case status::invalid_buffer_size:
            win32_error = ERROR_INVALID_USER_BUFFER;
            break;
        case status::invalid_handle:
            win32_error = ERROR_INVALID_HANDLE;
            break;
        case status::not_supported:
            win32_error = ERROR_NOT_SUPPORTED;
            break;
        case status::no_more_entries:
            win32_error = ERROR_NO_MORE_ITEMS;
            break;
        }
        return win32_error;
    }

    constexpr inline status nte_error_to_status(HRESULT nte_error) {
        //
        // NTE errors are subset of win32 error domain
        //
        status s{status::internal_error};

        switch (nte_error) {
        case ERROR_SUCCESS:
            s = status::success;
            break;
        case NTE_NO_MEMORY:
            s = status::insufficient_resources;
            break;
        case NTE_INVALID_PARAMETER:
            s = status::invalid_parameter;
            break;
        case NTE_INVALID_HANDLE:
            s = status::invalid_handle;
            break;
        case NTE_BUFFER_TOO_SMALL:
            s = status::buffer_too_small;
            break;
        case NTE_NOT_SUPPORTED:
            s = status::not_supported;
            break;
        case NTE_INTERNAL_ERROR:
            s = status::internal_error;
            break;
        case NTE_BAD_SIGNATURE:
            s = status::invalid_signature;
            break;
        case NTE_BAD_FLAGS:
            s = status::invalid_parameter;
            break;
        case NTE_NO_MORE_ITEMS:
            s = status::no_more_entries;
            break;
        case NTE_SILENT_CONTEXT:
            s = status::not_supported;
            break;
        case NTE_NOT_FOUND:
            s = status::not_found;
            break;
        default:
            s = status::internal_error;
            break;
        }
        return s;
    }

    constexpr inline HRESULT status_to_nte_error(status s) {
        HRESULT e{NTE_INTERNAL_ERROR};
        //
        // casting to underlying enumiration type
        // is a workaround to clang warning complainig that
        // we are comparing to a value that is not in the enumeration:
        //      case static_cast<status>(ERROR_INTERNAL_ERROR):
        //
        switch (long(s)) {
        case long(status::success):
            e = ERROR_SUCCESS;
            break;
        case long(status::no_memory):
            [[fallthrough]];
        case long(status::insufficient_resources):
            e = NTE_NO_MEMORY;
            break;
        case long(status::invalid_parameter):
            e = NTE_INVALID_PARAMETER;
            break;
        case long(status::invalid_handle):
            e = NTE_INVALID_HANDLE;
            break;
        case long(status::buffer_too_small):
            e = NTE_BUFFER_TOO_SMALL;
            break;
        case long(status::not_supported):
            e = NTE_NOT_SUPPORTED;
            break;
        case long(status::not_found):
            e = NTE_NOT_FOUND;
            break;
        case long(status::internal_error):
            [[fallthrough]];
        case ERROR_INTERNAL_ERROR:
            e = NTE_INTERNAL_ERROR;
            break;
        case long(status::invalid_signature):
            e = NTE_BAD_SIGNATURE;
            break;
        default:
            e = NTE_INTERNAL_ERROR;
            break;
        }

        return e;
    }

    inline DWORD nt_status_to_win32_error_ex(long const status) {
        return RtlNtStatusToDosError(status);
    }
} // namespace hcrypt

namespace std {
    //
    // declare that enumiration is an error code, NOT an
    // error condition
    //
    template<>
    struct is_error_code_enum<hcrypt::status>: public true_type {};
} // namespace std

namespace hcrypt {

    //
    // Define error category for Esent errors
    //
    class error_category_t: public std::error_category {
    public:
        virtual char const *name() const noexcept override {
            return "hcrypt_error";
        }

        virtual std::string message(int e) const override {
            // return status_to_string(static_cast<status>(e));
            return std::system_category().message(
                nt_status_to_win32_error_ex(static_cast<long>(e)));
        }

        virtual std::error_condition default_error_condition(int e) const noexcept override {
            return std::error_condition(
                status_to_win32_error(static_cast<hcrypt::status>(e)),
                std::system_category());
        }

        virtual bool equivalent(int e, const std::error_condition &cond) const
            noexcept override {
            return false;
        }
    };

    inline error_category_t const error_category_singleton;

    inline std::error_category const &get_error_category() noexcept {
        return error_category_singleton;
    }

    inline std::error_code make_error_code(status const s) noexcept {
        return {static_cast<int>(s), get_error_category()};
    }

    inline std::error_code make_error_code(long const s) noexcept {
        return make_error_code(static_cast<status>(s));
    }

    inline bool is_success(std::error_code const &err) {
        if (get_error_category() == err.category()) {
            return is_success(err.value());
        } else if (std::system_category() == err.category()) {
            return 0 == err.value();
        }
        BCRYPT_CRASH_APPLICATION();
        return false;
    }

    inline bool is_failure(std::error_code const &err) {
        if (get_error_category() == err.category()) {
            return is_failure(err.value());
        } else if (std::system_category() == err.category()) {
            return 0 != err.value();
        }
        BCRYPT_CRASH_APPLICATION();
        return false;
    }

    using buffer = std::vector<char>;

    [[nodiscard]] inline std::error_code try_resize(buffer &b, size_t new_size) noexcept {
        status s{status::success};
        try {
            b.resize(new_size);
        } catch (std::bad_alloc const &) {
            s = status::no_memory;
        } catch (...) {
            BCRYPT_CRASH_APPLICATION();
        }
        return s;
    }

    [[nodiscard]] inline std::error_code try_resize(buffer *b, size_t new_size) noexcept {
        return try_resize(*b, new_size);
    }

    [[nodiscard]] inline std::error_code try_resize(std::wstring &b, size_t new_size) noexcept {
        std::error_code s{status::success};
        try {
            b.resize(new_size);
        } catch (std::bad_alloc const &) {
            s = status::no_memory;
        } catch (...) {
            BCRYPT_CRASH_APPLICATION();
        }
        return s;
    }

    [[nodiscard]] inline std::error_code try_resize(std::wstring *b, size_t new_size) noexcept {
        return try_resize(*b, new_size);
    }

    inline void append_with_separator(std::wstring *str,
                                      std::wstring_view const &separator,
                                      std::wstring_view const &tail) {
        if (!str->empty()) {
            *str += separator;
        }
        *str += tail;
    }

    template<typename T>
    [[nodiscard]] constexpr inline T set_flag(T value, T flag) noexcept {
        return value | flag;
    }

    template<typename T>
    [[nodiscard]] constexpr inline bool is_flag_on(T value, T flag) noexcept {
        return (value & flag) == flag;
    }

    template<typename T>
    [[nodiscard]] constexpr inline T clear_flag(T value, T flag) noexcept {
        return value & ~flag;
    }

    template<typename T>
    [[nodiscard]] constexpr inline bool consume_flag(T *value, T flag) noexcept {
        bool is_on{is_flag_on(*value, flag)};
        if (is_on) {
            *value = clear_flag(*value, flag);
        }
        return is_on;
    }

    [[nodiscard]] constexpr inline size_t round_to_block(size_t size, size_t block_size) noexcept {
        return ((size + block_size - 1) / block_size) * block_size;
    }

    template<typename I, typename T>
    inline void to_hex(I cur, I const end, size_t group_size, wchar_t group_separator, T *result) {
        if (cur != end) {
            size_t cnt{0};
            while (cur != end) {
                unsigned char c{static_cast<unsigned char>(*cur++)};
                unsigned char l{static_cast<unsigned char>(c & 0x0F)};
                unsigned char h{static_cast<unsigned char>(c >> 4)};
                unsigned char r{
                    static_cast<unsigned char>(h < 10 ? '0' + h : 'A' + (h - 10))};
                result->push_back(static_cast<wchar_t>(r));
                r = l < 10 ? '0' + l : 'A' + (l - 10);
                result->push_back(static_cast<wchar_t>(r));

                // if we reached the group size then insert separtor
                if (++cnt == group_size) {
                    result->push_back(group_separator);
                    cnt = 0;
                }
            }
        }
    }

    template<typename I>
    inline std::wstring to_hex(I begin, I const end, size_t group_size = 0, wchar_t group_separator = L' ') {
        std::wstring result;

        to_hex(begin, end, group_size, group_separator, &result);

        return result;
    }

    template<typename C>
    inline std::wstring to_hex(C const &c, size_t group_size = 0, wchar_t group_separator = L' ') {
        std::wstring result;
        to_hex(std::begin(c), std::end(c), group_size, group_separator, &result);
        return result;
    }

    template<typename T, typename I>
    inline I from_hex(I &cur, I const &end, T *result) {
        size_t count{0};
        I prev{cur};

        while (cur != end) {
            prev = cur;
            auto c{*cur++};
            count++;
            unsigned char h{0};
            unsigned char l{0};

            if (c >= L'0' && c <= L'9') {
                h = static_cast<unsigned char>(c - L'0');
            } else if (c >= L'A' && c <= L'F') {
                h = static_cast<unsigned char>((c - L'A') + 10);
            } else if ((c >= L'a' && c <= L'f')) {
                h = static_cast<unsigned char>((c - L'a') + 10);
            } else {
                return false;
            }

            if (cur != end) {
                prev = cur;
                c = *cur++;
                count++;
                if (c >= L'0' && c <= L'9') {
                    l = static_cast<unsigned char>(c - L'0');
                } else if (c >= L'A' && c <= L'F') {
                    l = static_cast<unsigned char>((c - L'A') + 10);
                } else if ((c >= L'a' && c <= L'f')) {
                    l = static_cast<unsigned char>((c - L'a') + 10);
                } else {
                    return false;
                }
            }
            unsigned char r = (h << 4) | l;
            result->push_back(r);
        }
        //
        // if we finish and have processed an odd number of characters,
        // then we canot form correct byte so we have to return iterator
        // to previous processed character
        //
        return ((count % 2) == 0) ? cur : prev;
    }

    // clang-format off
    inline constexpr char const base64_encoding_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };
    // clang-format on

    inline size_t get_base64_length(size_t buffer_size) {
        size_t length{(buffer_size / 3) * 4};
        if (buffer_size % 3) {
            length += 4;
        }
        return length;
    }

    template<typename I>
    inline void to_base64(unsigned char const *buffer, size_t buffer_size, I out) {
        unsigned char const *cur{buffer};
        unsigned char const *end{buffer + buffer_size};
        unsigned char code[4];
        //
        // Fast case
        //
        for (; cur + 3 <= end; cur += 3) {
            code[0] = (cur[0] & 0b1111'1100) >> 2;
            code[1] = ((cur[0] & 0b0000'0011) << 4) + ((cur[1] & 0b1111'0000) >> 4);
            code[2] = ((cur[1] & 0b0000'1111) << 2) + ((cur[2] & 0b1100'0000) >> 6);
            code[3] = (cur[2] & 0b0011'1111);

            *out = base64_encoding_table[code[0]];
            ++out;
            *out = base64_encoding_table[code[1]];
            ++out;
            *out = base64_encoding_table[code[2]];
            ++out;
            *out = base64_encoding_table[code[3]];
            ++out;
        }
        //
        // Special cases at the tail
        //
        switch (buffer_size % 3) {
        case 2:
            code[0] = (cur[0] & 0b1111'1100) >> 2;
            code[1] = ((cur[0] & 0b0000'0011) << 4) + ((cur[1] & 0b1111'0000) >> 4);
            code[2] = (cur[1] & 0b0000'1111) << 2;

            *out = base64_encoding_table[code[0]];
            ++out;
            *out = base64_encoding_table[code[1]];
            ++out;
            *out = base64_encoding_table[code[2]];
            ++out;
            *out = '=';
            ++out;
            break;
        case 1:
            code[0] = (cur[0] & 0b1111'1100) >> 2;
            code[1] = (cur[0] & 0b0000'0011) << 4;

            *out = base64_encoding_table[code[0]];
            ++out;
            *out = base64_encoding_table[code[1]];
            ++out;
            *out = '=';
            ++out;
            *out = '=';
            ++out;
        default:;
        }
    }

    template<typename I>
    inline void to_base64(char const *buffer, size_t buffer_size, I out) {
        to_base64(reinterpret_cast<unsigned char const *>(buffer), buffer_size, out);
    }

    [[nodiscard]] inline std::string to_base64(char const *buffer, size_t buffer_size) {
        std::string result;
        result.reserve(get_base64_length(buffer_size));
        to_base64(buffer, buffer_size, std::back_inserter(result));
        return result;
    }

    [[nodiscard]] inline std::string to_base64(unsigned char const *buffer, size_t buffer_size) {
        std::string result;
        result.reserve(get_base64_length(buffer_size));
        to_base64(buffer, buffer_size, std::back_inserter(result));
        return result;
    }

    // clang-format off
    //
    // Reverse mapping from ASCII code to a positions in base64_encoding_table.
    // For invalid characters, and for '=' index is 0xFF
    //
    inline constexpr unsigned char const base64_decoding_table[256] = {
   //0x00,      0x01,      0x02,      0x03,      0x04,      0x05,      0x06,      0x07
     0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x00
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x01
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x02
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x03
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x04
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0x3e /*+*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0x3f /*/*/ // 0x05
    ,0x34 /*0*/,0x35 /*1*/,0x36 /*2*/,0x37 /*3*/,0x38 /*4*/,0x39 /*5*/,0x3a /*6*/,0x3b /*7*/ // 0x06
    ,0x3c /*8*/,0x3d /*9*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*=*/,0xff /*-*/,0xff /*-*/ // 0x07
    ,0xff /*-*/,0x00 /*A*/,0x01 /*B*/,0x02 /*C*/,0x03 /*D*/,0x04 /*E*/,0x05 /*F*/,0x06 /*G*/ // 0x08
    ,0x07 /*H*/,0x08 /*I*/,0x09 /*J*/,0x0a /*K*/,0x0b /*L*/,0x0c /*M*/,0x0d /*N*/,0x0e /*O*/ // 0x09
    ,0x0f /*P*/,0x10 /*Q*/,0x11 /*R*/,0x12 /*S*/,0x13 /*T*/,0x14 /*U*/,0x15 /*V*/,0x16 /*W*/ // 0x0a
    ,0x17 /*X*/,0x18 /*Y*/,0x19 /*Z*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x0b
    ,0xff /*-*/,0x1a /*a*/,0x1b /*b*/,0x1c /*c*/,0x1d /*d*/,0x1e /*e*/,0x1f /*f*/,0x20 /*g*/ // 0x0c
    ,0x21 /*h*/,0x22 /*i*/,0x23 /*j*/,0x24 /*k*/,0x25 /*l*/,0x26 /*m*/,0x27 /*n*/,0x28 /*o*/ // 0x0d
    ,0x29 /*p*/,0x2a /*q*/,0x2b /*r*/,0x2c /*s*/,0x2d /*t*/,0x2e /*u*/,0x2f /*v*/,0x30 /*w*/ // 0x0e
    ,0x31 /*x*/,0x32 /*y*/,0x33 /*z*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x0f
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x10
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x11
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x12
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x13
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x14
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x15
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x16
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x17
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x18
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x19
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1a
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1b
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1c
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1d
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1e
    ,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/,0xff /*-*/ // 0x1f
    };
    // clang-format on

    inline int find_base64_decoding_index(int c) noexcept {
        char const *pos{std::find(
            std::begin(base64_encoding_table), std::end(base64_encoding_table), c)};
        if (pos != std::end(base64_encoding_table)) {
            return int(pos - base64_encoding_table);
        }
        return 0xFF;
    }

    inline bool is_base64_character(unsigned int const c) noexcept {
        return isalnum(c) || c == '+' || c == '/';
    }

    inline void print_base64_decoding_table() noexcept {
        printf("//0x00,      0x01,      0x02,      0x03,      0x04,      0x05, "
               "     0x06,      0x07\n");

        for (int c = 0; c < 256; ++c) {
            unsigned char j = c / 8;

            if (0 == c) {
                printf(" ");
            } else {
                printf(",");
            }

            printf("0x%02x", find_base64_decoding_index(c));

            if (is_base64_character(c) || c == '=') {
                printf(" /*%c*/", char(c));
            } else {
                printf(" /*-*/");
            }

            if (7 == c % 8) {
                printf(" // 0x%02x\n", (unsigned int) j);
            }
        }
    }

    inline bool is_base64_character_fast(unsigned int const c) noexcept {
        return base64_decoding_table[c] != 0xFF;
    }

    //
    // @brief Algorithm consumes input in blocks of 4 bytes
    //
    template<typename I>
    [[nodiscard]] inline std::pair<bool, unsigned char const *> from_base64(
        unsigned char const *buffer, size_t buffer_size, I out) {
        if (0 == buffer_size) {
            return std::pair{true, buffer};
        }
        //
        // Algorithms consumes data in blocks of 4 bytes
        //
        if (buffer_size % 4 != 0) {
            return std::pair{false, buffer};
        }

        unsigned char idx[4];
        unsigned char decoded[3];
        unsigned char const *cur{buffer};
        unsigned char const *end{buffer + buffer_size};

        //
        // Fast case
        //
        for (; cur < end; cur += 4) {
            idx[0] = base64_decoding_table[cur[0]];
            if (idx[0] == 0xFF) {
                break;
            }
            idx[1] = base64_decoding_table[cur[1]];
            if (idx[1] == 0xFF) {
                break;
            }
            idx[2] = base64_decoding_table[cur[2]];
            if (idx[2] == 0xFF) {
                break;
            }
            idx[3] = base64_decoding_table[cur[3]];
            if (idx[3] == 0xFF) {
                break;
            }

            decoded[0] = (idx[0] << 2) + ((idx[1] & 0b0011'0000) >> 4);
            decoded[1] = ((idx[1] & 0b0000'1111) << 4) + ((idx[2] & 0b0011'1100) >> 2);
            decoded[2] = ((idx[2] & 0b0000'0011) << 6) + idx[3];

            *out = decoded[0];
            ++out;
            *out = decoded[1];
            ++out;
            *out = decoded[2];
            ++out;
        }
        //
        // Special cases
        //
        if (cur + 4 == end) {
            if (cur[2] == '=' && cur[3] == '=') {
                if (idx[0] == 0xFF || idx[1] == 0xFF) {
                    return std::pair{false, cur};
                }
                decoded[0] = (idx[0] << 2) + ((idx[1] & 0b0011'0000) >> 4);
                *out = decoded[0];
                ++out;
            } else if (cur[2] != '=' && cur[3] == '=') {
                if (idx[0] == 0xFF || idx[1] == 0xFF || idx[2] == 0xFF) {
                    return std::pair{false, cur};
                }
                decoded[0] = (idx[0] << 2) + ((idx[1] & 0b0011'0000) >> 4);
                decoded[1] =
                    ((idx[1] & 0b0000'1111) << 4) + ((idx[2] & 0b0011'1100) >> 2);

                *out = decoded[0];
                ++out;
                *out = decoded[1];
                ++out;

            } else {
                //
                // this case should have been handled
                // by the main loop above unless we found
                // an invalid character
                //
                return std::pair{false, cur};
            }
        }

        return std::pair{true, cur};
    }

    template<typename I>
    [[nodiscard]] inline std::pair<bool, char const *> from_base64(char const *buffer,
                                                                   size_t buffer_size,
                                                                   I out) {
        auto result{from_base64(
            reinterpret_cast<unsigned char const *>(buffer), buffer_size, out)};
        return std::pair{result.first, reinterpret_cast<char const *>(result.second)};
    }

    [[nodiscard]] inline std::string from_base64(char const *buffer, size_t buffer_size) {
        std::string str;
        str.reserve((buffer_size / 4) * 3);
        auto [result, last] = from_base64(buffer, buffer_size, std::back_inserter(str));
        if (!result) {
            throw std::invalid_argument{
                "Buffer does not contain valid Base64 encoded string"};
        }
        return str;
    }

    [[nodiscard]] inline std::string from_base64(unsigned char const *buffer, size_t buffer_size) {
        std::string str;
        str.reserve((buffer_size / 4) * 3);
        auto [result, last] = from_base64(buffer, buffer_size, std::back_inserter(str));
        if (!result) {
            throw std::invalid_argument{
                "Buffer does not contain valid Base64 encoded string"};
        }
        return str;
    }

    // filetime_duration has the same layout as FILETIME; 100ns intervals
    using filetime_duration = std::chrono::duration<int64_t, std::ratio<1, 10'000'000>>;

    // January 1, 1601 (NT epoch) - January 1, 1970 (Unix epoch):
    inline constexpr std::chrono::duration<int64_t> const nt_to_unix_epoch{-11644473600LL};

    inline std::chrono::system_clock::time_point filetime_to_time_point(FILETIME ft) noexcept {
        filetime_duration ft_duration{(static_cast<long long>(ft.dwHighDateTime) << 32) |
                                      static_cast<long long>(ft.dwLowDateTime)};
        auto const ft_with_unix_epoch{ft_duration + nt_to_unix_epoch};
        return std::chrono::system_clock::time_point{
            std::chrono::duration_cast<std::chrono::system_clock::duration>(ft_with_unix_epoch)};
    }

    inline FILETIME time_point_to_filetime(std::chrono::system_clock::time_point tp) noexcept {
        auto const duration{
            std::chrono::duration_cast<filetime_duration>(tp.time_since_epoch())};
        auto const duration_with_nt_epoch{duration - nt_to_unix_epoch};
        long long const raw_count{duration_with_nt_epoch.count()};

        FILETIME ft;
        ft.dwHighDateTime = static_cast<unsigned long>(raw_count);
        ft.dwLowDateTime = static_cast<unsigned long>(raw_count >> 32);

        return ft;
    }

    inline FILETIME systemtime_to_filetime(SYSTEMTIME const &st) noexcept {
        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        return ft;
    }

    inline void filetime_to_systemtime(FILETIME const &ft, SYSTEMTIME *st) noexcept {
        FileTimeToSystemTime(&ft, st);
    }

    inline SYSTEMTIME filetime_to_systemtime(FILETIME const &ft) noexcept {
        SYSTEMTIME st;
        filetime_to_systemtime(ft, &st);
        return st;
    }

    inline std::string systemtime_to_string(SYSTEMTIME const &st) {
        return hcrypt::make_string("%04hu/%02hu/%02hu %02hu:%02hu:%02hu.%03hu",
                                   st.wYear,
                                   st.wMonth,
                                   st.wDay,
                                   st.wHour,
                                   st.wMinute,
                                   st.wSecond,
                                   st.wMilliseconds);
    }

    inline std::wstring systemtime_to_wstring(SYSTEMTIME const &st) {
        return hcrypt::make_wstring(
            L"%04hu/%02hu/%02hu %02hu:%02hu:%02hu.%03hu",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
    }

    inline std::string filetime_to_string(FILETIME ft) {
        return systemtime_to_string(filetime_to_systemtime(ft));
    }

    inline std::wstring filetime_to_wstring(FILETIME ft) {
        return systemtime_to_wstring(filetime_to_systemtime(ft));
    }
} // namespace hcrypt