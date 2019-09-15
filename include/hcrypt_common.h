#pragma once

#include <utility>
#include <type_traits>
#include <system_error>
#include <vector>
#include <string>
#include <string_view>

#include <windows.h>
#include <intrin.h>

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
#define BCRYPT_MAKE_SYSTEM_ERROR(E, T) std::system_error{ static_cast<int>(E), std::system_category(), (T) }
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

#define BCRUPT_PROPERTY_DECL(NAME, NAME_STR, TYPE, HELPER_TYPE, CAN_SET, CAN_QUERY) struct property_##NAME {\
        using type_t = TYPE;\
        using helper_type_t = HELPER_TYPE;\
        constexpr inline static bool can_set {CAN_SET};\
        constexpr inline static bool can_query{ CAN_QUERY };\
        constexpr static wchar_t const* get_name() {\
            return NAME_STR;\
        }\
    };

namespace hcrypt {

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
    constexpr inline T set_flag(T value, T flag) {
        return value | flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline bool is_flag_on(T value, T flag) {
        return (value & flag) == flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline T clear_flag(T value, T flag) {
        return value & ~flag;
    }

    template<typename T>
    [[nodiscard]]
    constexpr inline bool consume_flag(T *value, T flag) {
        bool is_on{ is_flag_on(*value, flag) };
        if (is_on) {
            *value = clear_flag(*value, flag);
        }
        return is_on;
    }

    [[nodiscard]]
    constexpr inline size_t round_to_block(size_t size, size_t block_size) {
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

    constexpr inline wchar_t const* status_to_string(NTSTATUS const status) {
        wchar_t const* str{ L"Unknown status" };
        switch (status) {
        case STATUS_SUCCESS :
            str = L"STATUS_SUCCESS";
            break;
        case STATUS_BUFFER_TOO_SMALL:
            str = L"STATUS_BUFFER_TOO_SMALL";
            break;
        case STATUS_INSUFFICIENT_RESOURCES:
            str = L"STATUS_INSUFFICIENT_RESOURCES";
            break;
        case STATUS_INVALID_SIGNATURE:
            str = L"STATUS_INVALID_SIGNATURE";
            break;
        case STATUS_AUTH_TAG_MISMATCH:
            str = L"STATUS_AUTH_TAG_MISMATCH";
            break;
        case STATUS_UNSUCCESSFUL:
            str = L"STATUS_UNSUCCESSFUL";
            break;
        case STATUS_NOT_FOUND:
            str = L"STATUS_NOT_FOUND";
            break;
        case STATUS_INVALID_PARAMETER:
            str = L"STATUS_INVALID_PARAMETER";
            break;
        case STATUS_NO_MEMORY:
            str = L"STATUS_NO_MEMORY";
            break;
        case STATUS_INVALID_BUFFER_SIZE:
            str = L"STATUS_INVALID_BUFFER_SIZE";
            break;
        case STATUS_INVALID_HANDLE:
            str = L"STATUS_INVALID_HANDLE";
            break;
        case STATUS_NOT_SUPPORTED:
            str = L"STATUS_NOT_SUPPORTED";
            break;
        }
        return str;
    }
}