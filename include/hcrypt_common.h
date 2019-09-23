#pragma once

#include <utility>
#include <type_traits>
#include <system_error>
#include <vector>
#include <string>
#include <string_view>

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#pragma comment (lib, "ntdll.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x0L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL  ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES  ((NTSTATUS)0xC000009AL)
#endif

#ifndef STATUS_INVALID_SIGNATURE
#define STATUS_INVALID_SIGNATURE  ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH  ((NTSTATUS)0xC000A002L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL  ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND  ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER  ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY  ((NTSTATUS)0xC0000017L)
#endif

#ifndef STATUS_INVALID_BUFFER_SIZE
#define STATUS_INVALID_BUFFER_SIZE  ((NTSTATUS)0xC0000206L)
#endif

#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE  ((NTSTATUS)0xC0000008L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED  ((NTSTATUS)0xC00000BBL)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(S) ((NTSTATUS)(S) >= STATUS_SUCCESS)
#endif

#ifndef BCRYPT_MAKE_SYSTEM_ERROR
#define BCRYPT_MAKE_SYSTEM_ERROR(E, T) std::system_error{ static_cast<int>(E), hcrypt::get_error_category(), (T) }
#endif 

#define BCRYPT_PLATFORM_FAIL_FAST(EC) {__debugbreak();__fastfail(EC);}

#ifndef BCRYPT_FAST_FAIL
#define BCRYPT_FAST_FAIL(EC) {BCRYPT_PLATFORM_FAIL_FAST(EC);}
#endif

#ifndef BCRYPT_CRASH_APPLICATION
#define BCRYPT_CRASH_APPLICATION() BCRYPT_FAST_FAIL(ENOTRECOVERABLE)
#endif

#ifndef BCRYPT_CODDING_ERROR_IF
#define BCRYPT_CODDING_ERROR_IF(C) if (C) {BCRYPT_FAST_FAIL(ENOTRECOVERABLE);} else {;}
#endif


#ifndef BCRYPT_CODDING_ERROR_IF_NOT
#define BCRYPT_CODDING_ERROR_IF_NOT(C) if (C) {;} else {BCRYPT_FAST_FAIL(ENOTRECOVERABLE);}
#endif

#ifndef BCRYPT_DBG_CODDING_ERROR_IF_NOT
#define BCRYPT_DBG_CODDING_ERROR_IF_NOT(C) BCRYPT_CODDING_ERROR_IF_NOT(C)
#endif

#ifndef BCRYPT_DBG_CODDING_ERROR_IF
#define BCRYPT_DBG_CODDING_ERROR_IF(C) BCRYPT_CODDING_ERROR_IF(C)
#endif

namespace hcrypt {

    inline void erase_tail_zeroes(std::string& str) {
        if (str.empty()) {
            return;
        }

        size_t idx{str.size() - 1};
        size_t count{ 0 };

        while (0 != idx && '\0' == str[idx]) {
            --idx;
            ++count;
        }

        if (count) {
            str.erase(idx, count);
        }
    }

    inline void erase_tail_zeroes(std::wstring& str) {
        if (str.empty()) {
            return;
        }

        size_t idx{ str.size() - 1 };
        size_t count{ 0 };

        while (0 != idx && L'\0' == str[idx]) {
            --idx;
            ++count;
        }

        if (count) {
            str.erase(idx, count);
        }
    }

    inline std::string v_make_string(char const* format, 
                                     va_list argptr) {
        size_t buffer_size = _vscprintf(format, argptr);

        int err{ 0 };

        if (-1 == buffer_size) {
            err = errno; 
            std::system_error{ err, 
                               std::generic_category(), 
                               "_vscprintf failed, invalid formatting string passed to v_make_string" };
        }

        std::string str;

        if (0 == buffer_size) {
            return str;
        }

        str.resize(buffer_size + 1);

        _vsnprintf_s(&str[0],
                     str.size(),
                     _TRUNCATE,
                     format,
                     argptr);

        if (-1 == buffer_size) {
            err = errno;
            std::system_error{ err, 
                               std::generic_category(), 
                               "_vsnprintf_s failed, invalid formatting string passed to v_make_string" };
        }

        erase_tail_zeroes(str);

        return str;
    }

    inline std::string make_string(char const* format, 
                                   ...) {
        va_list argptr;
        va_start(argptr, format);
        return v_make_string(format, argptr);
    }

    inline std::wstring v_make_wstring(wchar_t const* format, 
                                       va_list argptr) {
        size_t buffer_size = _vscwprintf(format, argptr);

        int err{ 0 };

        if (-1 == buffer_size) {
            err = errno;
            std::system_error{ err, 
                               std::generic_category(), 
                               "_vscwprintf failed, invalid formatting string passed to v_make_wstring" };
        }

        std::wstring str;

        if (0 == buffer_size) {
            return str;
        }
        
        str.resize(buffer_size + 1, 0);

        _vsnwprintf_s(&str[0],
                      str.size(),
                      _TRUNCATE,
                      format,
                      argptr);

        if (-1 == buffer_size) {
            err = errno;
            std::system_error{ err, 
                               std::generic_category(), 
                               "_vsnwprintf_s failed, invalid formatting string passed to v_make_wstring" };
        }

        erase_tail_zeroes(str);

        return str;
    }

    inline std::wstring make_wstring(wchar_t const* format, 
                                     ...) {
        va_list argptr;
        va_start(argptr, format);
        return v_make_wstring(format, argptr);
    }

    inline std::wstring a_to_u(char const *in_str,
                               UINT codepage = CP_ACP,
                               DWORD flags = 0) {

        DWORD err{ ERROR_SUCCESS };
        std::wstring out_str;

        int size{ ::MultiByteToWideChar(codepage,
                                        flags,
                                        in_str,
                                        -1,
                                        nullptr,
                                        0) };

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                std::system_error{ static_cast<int>(err), 
                                   std::system_category(), 
                                   "MultiByteToWideChar failed while estimating size" };
            } 
            return out_str;
        }

        out_str.resize(size);

        size = ::MultiByteToWideChar(codepage,
                                     flags,
                                     in_str,
                                     -1,
                                     &out_str[0],
                                     size);

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                std::system_error{ static_cast<int>(err),
                                   std::system_category(), 
                                   "MultiByteToWideChar failed while estimating size" };
            }
        }

        erase_tail_zeroes(out_str);

        return out_str;
    }

    inline std::wstring a_to_u(std::string const &in_str,
                               UINT codepage = CP_ACP,
                               DWORD flags = 0) {
        return a_to_u(in_str.c_str(),
                      codepage,
                      flags);
    }

    inline std::string u_to_a(wchar_t const *in_str,
                              UINT codepage = CP_ACP,
                              DWORD flags = 0,
                              char const *default_char = nullptr,
                              bool *is_default_used = nullptr) {
        DWORD err{ ERROR_SUCCESS };
        std::string out_str;
        BOOL is_default_used_tmp = FALSE;

        int size{ ::WideCharToMultiByte(codepage,
                                        flags,
                                        in_str,
                                        -1,
                                        NULL,
                                        0,
                                        nullptr,
                                        nullptr) };

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                std::system_error{ static_cast<int>(err),
                                   std::system_category(), 
                                   "WideCharToMultiByte failed while estimating size" };
            } 
            return out_str;
        }

        out_str.resize(size);

        size = ::WideCharToMultiByte(codepage,
                                     flags,
                                     in_str,
                                     -1,
                                     &out_str[0],
                                     size,
                                     default_char,
                                     &is_default_used_tmp);

        if (0 == size) {
            err = GetLastError();
            if (ERROR_SUCCESS != err) {
                std::system_error{ static_cast<int>(err),
                                   std::system_category(), 
                                   "WideCharToMultiByte failed while estimating size" };
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
        return u_to_a(in_str.c_str(),
                      codepage,
                      flags,
                      default_char,
                      is_default_used);
    }

    enum class status : long {
        success                 = 0L,
        unsuccessful            = static_cast<long>(0xC0000001L),
        invalid_handle          = static_cast<long>(0xC0000008L),
        no_memory               = static_cast<long>(0xC0000017L),
        buffer_too_small        = static_cast<long>(0xC0000023L),
        insufficient_resources  = static_cast<long>(0xC000009AL),
        invalid_parameter       = static_cast<long>(0xC000000DL),
        invalid_buffer_size     = static_cast<long>(0xC0000206L),
        not_found               = static_cast<long>(0xC0000225L),
        not_supported           = static_cast<long>(0xC00000BBL),
        invalid_signature       = static_cast<long>(0xC000A000L),
        auth_tag_mismatch       = static_cast<long>(0xC000A002L),
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

    constexpr inline char const* try_status_to_string(status const status) {
        char const* str{ nullptr };
        switch (status) {
        case status::success:
            str = "success";
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
        case status::invalid_parameter:
            str = "invalid_parameter";
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

    constexpr inline char const* status_to_string(status const status) {
        char const* str{ try_status_to_string(status) };
        if (nullptr == str) {
            str = "unknown status";
        }
        return str;
    }

    constexpr inline char const* status_to_string(int const s) {
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
        case status::invalid_parameter:
            win32_error = ERROR_INVALID_PARAMETER;
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
        }
        return win32_error;
    }

    inline DWORD nt_status_to_win32_error_ex(long const status) {
        return RtlNtStatusToDosError(status);
    }
}

namespace std {
    //
    // declare that enumiration is an error code, NOT an
    // error condition
    //
    template <>
    struct is_error_code_enum<hcrypt::status> : public true_type {};
 }

namespace hcrypt {

    //
    // Define error category for Esent errors
    //
    class error_category_t
        : public std::error_category {
    public:

        virtual char const* name() const noexcept override {
            return "hcrypt_error";
        }

        virtual std::string message(int e) const override {
            //return status_to_string(static_cast<status>(e));
            return std::system_category().message(nt_status_to_win32_error_ex(static_cast<long>(e)));
        }

        virtual std::error_condition default_error_condition(int e) const noexcept override {
            return std::error_condition(status_to_win32_error(static_cast<hcrypt::status>(e)),
                                        std::system_category());
        }

        virtual bool equivalent(int e, const std::error_condition& cond) const noexcept {
            return false;
        }
    };

    inline error_category_t const error_category_singleton;

    inline std::error_category const& get_error_category() noexcept {
        return error_category_singleton;
    }

    inline std::error_code make_error_code(status const s) noexcept {
        return { static_cast<int>(s), get_error_category() };
    }

    inline std::error_code make_error_code(long const s) noexcept {
        return make_error_code(static_cast<status>(s));
    }

    inline bool is_success(std::error_code const& err) {
        BCRYPT_DBG_CODDING_ERROR_IF_NOT(get_error_category() == err.category());
        return is_success(err.value());
    }

    inline bool is_failure(std::error_code const& err) {
        BCRYPT_DBG_CODDING_ERROR_IF_NOT(get_error_category() == err.category());
        return is_failure(err.value());
    }

    using buffer = std::vector<char>;

    [[nodiscard]]
    inline NTSTATUS try_resize(buffer &b, 
                               size_t new_size) noexcept {
        NTSTATUS status{ STATUS_SUCCESS };
        try{
            b.resize(new_size);
        } catch (std::bad_alloc const&) {
            status = STATUS_NO_MEMORY;
        } catch(...) {
            BCRYPT_CRASH_APPLICATION();
        }
        return status;
    }

    [[nodiscard]]
    inline NTSTATUS try_resize(buffer *b, 
                               size_t new_size) noexcept {
        return try_resize(*b, new_size);
    }

    [[nodiscard]]
    inline NTSTATUS try_resize(std::wstring& b, 
                               size_t new_size) noexcept {
        NTSTATUS status{ STATUS_SUCCESS };
        try {
            b.resize(new_size);
        } catch (std::bad_alloc const&) {
            status = STATUS_NO_MEMORY;
        } catch (...) {
            BCRYPT_CRASH_APPLICATION();
        }
        return status;
    }

    [[nodiscard]]
    inline NTSTATUS try_resize(std::wstring* b, size_t new_size) noexcept {
        return try_resize(*b, new_size);
    }

    inline void append_with_separator(std::wstring *str,
                                      std::wstring_view const &separator, 
                                      std::wstring_view const &tail) {
        if (str->empty()) {
            *str += separator;
        }
        *str += tail;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline T set_flag(T value, T flag) noexcept {
        return value | flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline bool is_flag_on(T value, T flag) noexcept {
        return (value & flag) == flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline T clear_flag(T value, T flag) noexcept {
        return value & ~flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline bool consume_flag(T *value, T flag) noexcept {
        bool is_on{ is_flag_on(*value, flag) };
        if (is_on) {
            *value = clear_flag(*value, flag);
        }
        return is_on;
    }

    [[nodiscard]]
    constexpr inline size_t round_to_block(size_t size, size_t block_size) noexcept {
        return ((size + block_size - 1) / block_size) * block_size;
    }

    template< typename I, typename T >
    inline void to_hex( I cur,
                        I const end ,
                        size_t group_size,
                        wchar_t group_separator,
                        T *result ) {
        if(cur != end) {
            size_t cnt{ 0 };
            while( cur != end ) {
                unsigned char c{ static_cast<unsigned char>(*cur++) };
                unsigned char l{ static_cast<unsigned char>(c & 0x0F) };
                unsigned char h{ static_cast<unsigned char>(c >> 4) };
                unsigned char r{ static_cast<unsigned char>(h < 10 ? '0' + h
                                                                   : 'A' + (h - 10)) };
                result->push_back( static_cast<wchar_t>( r ) );
                r = l < 10 ? '0' + l
                           : 'A' + ( l - 10 );
                result->push_back( static_cast<wchar_t>( r ) );

                //if we reached the group size then insert separtor
                if(++cnt == group_size ) {
                    result->push_back(group_separator);
                    cnt = 0;
                }
            }
        }
    }

    template< typename I >
    inline std::wstring to_hex( I begin,
                                I const end ,
                                size_t group_size = 0,
                                wchar_t group_separator = L' ') {
        std::wstring result;
        
        to_hex(begin,
               end,
               group_size,
               group_separator,
               &result);

        return result;
     }

    template< typename C >
    inline std::wstring to_hex( C const &c,
                                size_t group_size = 0,
                                wchar_t group_separator = L' ') {
        std::wstring result;
        to_hex(std::begin(c),
               std::end(c),
               group_size,
               group_separator,
               &result);
        return result;
     }

    template< typename T, typename I >
    inline I from_hex( I & cur, I const& end, T *result ) {
        
        size_t count{ 0 };
        I prev{ cur };

        while( cur != end ) {
            prev = cur;
            auto c{ *cur++ };
            count++;
            unsigned char h{ 0 };
            unsigned char l{ 0 };

            if( c >= L'0' && c <= L'9' ) {
                h = static_cast<unsigned char>( c - L'0' );
            } else if( c >= L'A' && c <= L'F' ) {
                h = static_cast<unsigned char>( ( c - L'A' ) + 10 );
            } else if( ( c >= L'a' && c <= L'f' ) ) {
                h = static_cast<unsigned char>( ( c - L'a' ) + 10 );
            } else {
                return false;
            }

            if( cur != end ) {
                prev = cur;
                c = *cur++;
                count++;
                if( c >= L'0' && c <= L'9' ) {
                    l = static_cast<unsigned char>( c - L'0' );
                } else if( c >= L'A' && c <= L'F' ) {
                    l = static_cast<unsigned char>( ( c - L'A' ) + 10 );
                } else if( ( c >= L'a' && c <= L'f' ) ) {
                    l = static_cast<unsigned char>( ( c - L'a' ) + 10 );
                } else {
                    return false;
                }
            }
            unsigned char r = ( h << 4 ) | l;
            result->push_back( r );
        }
        //
        // if we finish and have processed an odd number of characters, 
        // then we canot form correct byte so we have to return iterator
        // to previous processed character
        //
        return ((count % 2) == 0) ? cur : prev;
    }
}