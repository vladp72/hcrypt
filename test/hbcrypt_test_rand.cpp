#include "hbcrypt_test_rand.hpp"

namespace {

    void test_global(int offset) {
        printf("\n%*cTesting Global functions\n", offset, ' ');

        char b1[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

        bcrypt::generate_random(b1, sizeof(b1));

        printf("%*cbuffer: %S\n",
               offset,
               ' ',
               hcrypt::to_hex(std::begin(b1), std::end(b1)).c_str());

        unsigned char ub{bcrypt::generate_random<unsigned char>()};

        printf("%*cunsigned char: %i\n", offset, ' ', static_cast<int>(ub));

        unsigned short us{bcrypt::generate_random<unsigned short>()};

        printf("%*cunsigned short: %hu\n", offset, ' ', us);

        unsigned long ul{bcrypt::generate_random<unsigned long>()};

        printf("%*cunsigned long: %u\n", offset, ' ', ul);

        unsigned long long ull{bcrypt::generate_random<unsigned long long>()};

        printf("%*cunsigned long long: %llu\n", offset, ' ', ull);

        double d{bcrypt::generate_random<double>()};

        printf("%*cdouble: %a\n", offset, ' ', d);
    }

    void test_provider(int offset, wchar_t const *algorithm, wchar_t const *provider = nullptr) {
        try {
            printf("\n%*cTesting algorithm %S, provider %S\n",
                   offset,
                   ' ',
                   algorithm ? algorithm : L"",
                   provider ? provider : L"");

            bcrypt::algorithm_provider ap{algorithm, provider};
            print_object_properties(offset + 2, ap, true);

            char b1[] = {
                0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

            ap.generate_random(b1, sizeof(b1));

            printf("%*cbuffer: %S\n",
                   offset,
                   ' ',
                   hcrypt::to_hex(std::begin(b1), std::end(b1)).c_str());

            unsigned char ub{ap.generate_random<unsigned char>()};

            printf("%*cunsigned char: %i\n", offset, ' ', static_cast<int>(ub));

            unsigned short us{ap.generate_random<unsigned short>()};

            printf("%*cunsigned short: %hu\n", offset, ' ', us);

            unsigned long ul{ap.generate_random<unsigned long>()};

            printf("%*cunsigned long: %u\n", offset, ' ', ul);

            unsigned long long ull{ap.generate_random<unsigned long long>()};

            printf("%*cunsigned long long: %llu\n", offset, ' ', ull);

            double d{ap.generate_random<double>()};

            printf("%*cdouble: %a\n", offset, ' ', d);

        } catch (std::system_error const &ex) {
            printf("%*ctest_provider, error code = %x, %s\n",
                   offset,
                   ' ',
                   ex.code().value(),
                   ex.what());
        }
    }

} // namespace

void test_rand() {
    try {
        int offset{0};

        printf("\n---Generate random ---------------\n");

        test_global(offset);

        test_provider(offset, BCRYPT_RNG_ALGORITHM);
        test_provider(offset, BCRYPT_RNG_DUAL_EC_ALGORITHM);
        test_provider(offset, BCRYPT_RNG_FIPS186_DSA_ALGORITHM);

    } catch (std::system_error const &ex) {
        printf("test_rand, error code = %x, %s\n", ex.code().value(), ex.what());
    }
    printf("/n----------------\n");
}
