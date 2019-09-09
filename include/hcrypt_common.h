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