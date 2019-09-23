#include "hbcrypt_test_CTAD.h"

void test_CTAD() {

    bcrypt::buffer_ptr void_ptr;
    static_assert(std::is_same_v<decltype(void_ptr), bcrypt::buffer_ptr<void>>);
    bcrypt::buffer_ptr void_ptr2( std::move(void_ptr) );
    static_assert(std::is_same_v<decltype(void_ptr2), bcrypt::buffer_ptr<void>>);

    int* p{ nullptr };

    bcrypt::buffer_ptr int_ptr(p);
    static_assert(std::is_same_v<decltype(int_ptr), bcrypt::buffer_ptr<int>>);
}
