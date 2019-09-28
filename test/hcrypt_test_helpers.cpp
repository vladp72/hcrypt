#include "hcrypt_test_helpers.hpp"

void print(int offset, CRYPT_INTERFACE_REG const *interface_registartion) {
    printf("%*cinterface = %lu, %ws\n",
           offset,
           ' ',
           interface_registartion->dwInterface,
           bcrypt::interface_id_to_string(interface_registartion->dwInterface));
    printf("%*cflags     = %lu %ws\n",
           offset,
           ' ',
           interface_registartion->dwFlags,
           bcrypt::interface_flags_to_string(interface_registartion->dwFlags).c_str());
    for (ULONG idx = 0; idx < interface_registartion->cFunctions; ++idx) {
        printf("%*cfunction: %ws\n", offset + 2, ' ', interface_registartion->rgpszFunctions[idx]);
    }
}

void print(int offset, CRYPT_IMAGE_REG const *registartion) {
    printf("%*cimage: %ws\n", offset, ' ', registartion->pszImage);
    for (ULONG idx = 0; idx < registartion->cInterfaces; ++idx) {
        print(offset + 2, registartion->rgpInterfaces[idx]);
    }
}

void print(int offset, CRYPT_PROPERTY_REF const *property_ref) {
    printf("%*cproperty: %ws, bytes %lu",
           offset,
           ' ',
           property_ref->pszProperty,
           property_ref->cbValue);

    if (4 == property_ref->cbValue) {
        printf(", value %lu", *reinterpret_cast<ULONG const *>(property_ref->pbValue));
    }
    printf("\n");
}

void print(int offset, CRYPT_IMAGE_REF const *image_ref) {
    printf("%*cimage: %ws, flags 0x%lx, %ws\n",
           offset,
           ' ',
           image_ref->pszImage,
           image_ref->dwFlags,
           bcrypt::image_flags_to_string(image_ref->dwFlags).c_str());
}

void print(int offset, CRYPT_PROVIDER_REF const *provider_ref) {
    printf("%*cprovider: %ws, function - %ws; itf - %lu, %ws\n",
           offset,
           ' ',
           provider_ref->pszProvider,
           provider_ref->pszFunction,
           provider_ref->dwInterface,
           bcrypt::interface_id_to_string(provider_ref->dwInterface));

    for (ULONG idx = 0; idx < provider_ref->cProperties; ++idx) {
        print(offset + 2, provider_ref->rgpProperties[idx]);
    }

    if (provider_ref->pUM) {
        print(offset + 2, provider_ref->pUM);
    }

    if (provider_ref->pKM) {
        print(offset + 2, provider_ref->pKM);
    }
}

void print(int offset, CRYPT_PROVIDER_REFS const *interface_registartion_ref) {
    for (ULONG idx = 0; idx < interface_registartion_ref->cProviders; ++idx) {
        print(offset + 2, interface_registartion_ref->rgpProviders[idx]);
    }
}

void print(int offset, BCRYPT_ALGORITHM_IDENTIFIER const *algorithm_info) {
    printf("%*cname: %ws, class %ws, flags 0x%lx\n",
           offset,
           ' ',
           algorithm_info->pszName,
           bcrypt::interface_id_to_string(algorithm_info->dwClass),
           algorithm_info->dwFlags);
}

void print(int offset, bcrypt::crypto_context_function_cptr const &crypto_context_functions) {
    bcrypt::find_first(crypto_context_functions, [offset](wchar_t const *context_name) -> bool {
        printf("%*cfunction: %ws\n", offset, ' ', context_name);

        return true;
    });
}
