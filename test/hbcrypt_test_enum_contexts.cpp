#include "hbcrypt_test_enum_contexts.hpp"

namespace {

    void print_crypto_context(int offset, ULONG table) {
        printf("%*ctable: %ws\n", offset, ' ', bcrypt::table_to_string(table));

        bcrypt::find_first(
            bcrypt::enum_crypto_context(table),
            [offset = offset + 2, table](wchar_t const *context_name) -> bool {
                printf("%*ccontext: %ws\n", offset, ' ', context_name);

                bcrypt::find_first_interface([offset = offset + 2, table, context_name](
                                                 ULONG itf_id) -> bool {
                    printf("%*cinterface: %ws\n", offset, ' ', bcrypt::interface_id_to_string(itf_id));

                    try {
                        bcrypt::find_first(
                            bcrypt::enum_crypto_context_function(table, context_name, itf_id),
                            [offset = offset + 2, table, context_name, itf_id](
                                wchar_t const *function_name) -> bool {
                                printf("%*cfunction: %ws\n", offset, ' ', function_name);

                                try {
                                    bcrypt::find_first(
                                        bcrypt::enum_crypto_context_function_providers(
                                            table, context_name, itf_id, function_name),
                                        [offset = offset + 2](wchar_t const *provider_name) -> bool {
                                            printf("%*cprovider: %ws\n", offset, ' ', provider_name);
                                            return true;
                                        });

                                } catch (std::system_error const &ex) {
                                    printf("%*cenum_crypto_context_function, "
                                           "error code = 0x%x, %s\n",
                                           offset,
                                           ' ',
                                           ex.code().value(),
                                           ex.what());
                                }

                                return true;
                            });

                    } catch (std::system_error const &ex) {
                        printf("%*cenum_crypto_context_function, error code = "
                               "0x%x, %s\n",
                               offset,
                               ' ',
                               ex.code().value(),
                               ex.what());
                    }
                    return true;
                });
                return true;
            });
    }
} // namespace

void print_crypto_contexts() {
    try {
        int offset{0};

        printf("---Enumirating crypto contexts---------------\n");

        print_crypto_context(offset + 2, CRYPT_LOCAL);
        print_crypto_context(offset + 2, CRYPT_DOMAIN);

    } catch (std::system_error const &ex) {
        printf("print_crypto_contexts, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("----------------\n");
}
