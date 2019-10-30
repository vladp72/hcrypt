#include "hbcrypt_test_base64.hpp"
#include <array>

namespace {

    template<typename C>
    void print_container(int offset, char const *title, C const &c) {
        printf("%*c%s \"", offset, ' ', title);
        for (auto v : c) {
            printf("%c", v);
        }
        printf("\"\n");
    }

    template<typename C>
    void print_container_hex(int offset, char const *title, C const &c) {
        printf("%*c%s \"", offset, ' ', title);
        for (auto v : c) {
            printf("%02x", v);
        }
        printf("\"\n");
    }

    void test_base64(int offset, std::string_view const &in) {
        std::string encoded;
        print_container(offset, "data    :", in);
        print_container_hex(offset, "hex     :", in);
        hcrypt::to_base64(in.data(), in.size(), std::back_inserter(encoded));
        print_container(offset, "encoded :", encoded);

        std::string other_encoded{hcrypt::binary_to_string(
            in.data(), in.length(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF)};
        BCRYPT_CODDING_ERROR_IF_NOT(encoded == other_encoded);

        hcrypt::buffer decoded;
        auto [result, iter] = hcrypt::from_base64(
            encoded.data(), encoded.size(), std::back_inserter(decoded));
        BCRYPT_CODDING_ERROR_IF(false == result);
        print_container(offset, "decoded :", decoded);

        BCRYPT_CODDING_ERROR_IF_NOT(
            in == std::string_view(decoded.data(), decoded.size()));

        hcrypt::buffer other_decoded{hcrypt::string_to_binary(other_encoded, CRYPT_STRING_BASE64)};
        BCRYPT_CODDING_ERROR_IF_NOT(
            in == std::string_view(other_decoded.data(), other_decoded.size()));
    }

    void test_base64_decoding_bad_input(int offset, std::string_view const &in) {
        hcrypt::buffer decoded;
        print_container(offset, "data    :", in);
        print_container_hex(offset, "hex     :", in);
        auto [result, iter] =
            hcrypt::from_base64(in.data(), in.size(), std::back_inserter(decoded));
        BCRYPT_CODDING_ERROR_IF(true == result);
        print_container(offset, "decoded :", decoded);
    }

    std::array<std::string_view, 14> data{{std::string_view{""},
                                           std::string_view{"#"},
                                           std::string_view{"##"},
                                           std::string_view{"###"},
                                           std::string_view{"####"},
                                           std::string_view{"#####"},
                                           std::string_view{"######"},
                                           std::string_view{"#######"},
                                           std::string_view{"########"},
                                           std::string_view{"#########"},
                                           std::string_view{"##########"},
                                           std::string_view{"###########"},
                                           std::string_view{"############"},
                                           std::string_view{"#############"}}};

    std::array<std::string_view, 26> bad_encoding{{
        std::string_view{"="},         std::string_view{"=="},
        std::string_view{"===="},      std::string_view{"====="},
        std::string_view{"@"},         std::string_view{"@@"},
        std::string_view{"@@@@"},      std::string_view{"I=w="},
        std::string_view{"Iw="},       std::string_view{"Iw=@"},
        std::string_view{"Iw@="},      std::string_view{"I@=="},
        std::string_view{"@w=="},      std::string_view{"IyMj="},
        std::string_view{"IyMj=="},    std::string_view{"IyMj===="},
        std::string_view{"IyMj====="}, std::string_view{"IyMj@"},
        std::string_view{"IyMj@@"},    std::string_view{"IyMj@@@@"},
        std::string_view{"IyMjI=w="},  std::string_view{"IyMjIw="},
        std::string_view{"IyMjIw=@"},  std::string_view{"IyMjIw@="},
        std::string_view{"IyMjI@=="},  std::string_view{"IyMj@w=="},
    }};

} // namespace

void test_base64() {
    printf("\n---test_base64---------------\n");

    hcrypt::print_base64_decoding_table();

    for (auto const &v : data) {
        test_base64(1, v);
    }

    printf("\n---test_base64_decoding_bad_input---------------\n");

    for (auto const &v : bad_encoding) {
        test_base64_decoding_bad_input(1, v);
    }
    printf("\n----------------\n");
}
