// ConsoleApplication13.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "credman_tests.hpp"

#include <credman.hpp>
#include <credman_ui.hpp>

//#include <credman_ui.hpp>

void print(int identation, CREDENTIAL_ATTRIBUTEW const &cred, size_t idx = 0) {
    printf("%*c [%Iu] CREDENTIAL_ATTRIBUTEW.Keyword   %S\n", identation, ' ', idx, cred.Keyword);
    printf("%*c [%Iu] CREDENTIAL_ATTRIBUTEW.Flags     %lu\n", identation, ' ', idx, cred.Flags);
    printf("%*c [%Iu] CREDENTIAL_ATTRIBUTEW.ValueSize %lu\n", identation, ' ', idx, cred.ValueSize);
    printf("%*c [%Iu] CREDENTIAL_ATTRIBUTEW.Value     %S\n",
           identation,
           ' ',
           idx,
           cred.ValueSize
               ? hcrypt::to_hex(cred.Value, cred.Value + cred.ValueSize).c_str()
               : L"");
}

void print(int identation, CREDENTIALW const &cred, size_t idx = 0) {
    printf("%*c [%Iu] CREDENTIALW.Flags              %lu, %S\n",
           identation,
           ' ',
           idx,
           cred.Flags,
           credman::credential_flags_to_string(cred.Flags).c_str());
    printf("%*c [%Iu] CREDENTIALW.Type               %lu, %S\n",
           identation,
           ' ',
           idx,
           cred.Type,
           credman::credential_type_to_string(cred.Type));
    printf("%*c [%Iu] CREDENTIALW.TargetName         %S\n",
           identation,
           ' ',
           idx,
           cred.TargetName ? cred.TargetName : L"");
    printf("%*c [%Iu] CREDENTIALW.Comment            %S\n",
           identation,
           ' ',
           idx,
           cred.Comment ? cred.Comment : L"");
    printf("%*c [%Iu] CREDENTIALW.LastWritten        %S\n",
           identation,
           ' ',
           idx,
           hcrypt::filetime_to_wstring(cred.LastWritten).c_str());
    printf("%*c [%Iu] CREDENTIALW.CredentialBlobSize %lu\n", identation, ' ', idx, cred.CredentialBlobSize);

    std::wstring blob_str;
    if (cred.CredentialBlobSize) {
        switch (cred.Type) {
        case CRED_TYPE_DOMAIN_PASSWORD:
        case CRED_TYPE_DOMAIN_CERTIFICATE:
            blob_str.assign(reinterpret_cast<wchar_t const *>(cred.CredentialBlob),
                            reinterpret_cast<wchar_t const *>(cred.CredentialBlob) +
                                (cred.CredentialBlobSize) / sizeof(wchar_t));

            printf("%*c [%Iu] CREDENTIALA.CredentialBlobStr  %S\n",
                   identation,
                   ' ',
                   idx,
                   blob_str.c_str());

            break;
        }
    }

    printf("%*c [%Iu] CREDENTIALA.CredentialBlob     %S\n",
           identation,
           ' ',
           idx,
           cred.CredentialBlobSize
               ? hcrypt::to_hex(cred.CredentialBlob, cred.CredentialBlob + cred.CredentialBlobSize)
                     .c_str()
               : L"");
    printf("%*c [%Iu] CREDENTIALA.Persist            %lu, %S\n",
           identation,
           ' ',
           idx,
           cred.Persist,
           credman::credential_persist_type_to_string(cred.Persist));
    printf("%*c [%Iu] CREDENTIALA.AttributeCount     %lu\n", identation, ' ', idx, cred.AttributeCount);
    for (size_t i = 0; i < cred.AttributeCount; ++i) {
        print(identation + 2, cred.Attributes[i], i);
    }
    printf("%*c [%Iu] CREDENTIALA.TargetAlias        %S\n",
           identation,
           ' ',
           idx,
           cred.TargetAlias ? cred.TargetAlias : L"");
    printf("%*c [%Iu] CREDENTIALA.UserName           %S\n",
           identation,
           ' ',
           idx,
           cred.UserName ? cred.UserName : L"");
}

void print(int identation, CREDENTIAL_TARGET_INFORMATIONW const &target, size_t idx = 0) {
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.TargetName           %S\n",
           identation,
           ' ',
           idx,
           target.TargetName ? target.TargetName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.NetbiosServerName    %S\n",
           identation,
           ' ',
           idx,
           target.NetbiosServerName ? target.NetbiosServerName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.DnsServerName        %S\n",
           identation,
           ' ',
           idx,
           target.DnsServerName ? target.DnsServerName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.NetbiosDomainName    %S\n",
           identation,
           ' ',
           idx,
           target.NetbiosDomainName ? target.NetbiosDomainName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.DnsDomainName        %S\n",
           identation,
           ' ',
           idx,
           target.DnsDomainName ? target.DnsDomainName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.DnsTreeName          %S\n",
           identation,
           ' ',
           idx,
           target.DnsTreeName ? target.DnsTreeName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.PackageName          %S\n",
           identation,
           ' ',
           idx,
           target.PackageName ? target.PackageName : L"");
    printf("%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.Flags                "
           "0x%lx, %S\n",
           identation,
           ' ',
           idx,
           target.Flags,
           credman::target_info_flags_to_string(target.Flags).c_str());
    printf(
        "%*c [%Iu] CREDENTIAL_TARGET_INFORMATIONW.CredTypeCount        %lu\n",
        identation,
        ' ',
        idx,
        target.CredTypeCount);

    for (ULONG i = 0; i < target.CredTypeCount; ++i) {
        printf("%*c [%Iu, %lu] CREDENTIAL_TARGET_INFORMATIONW.CredTypes %lu\n",
               identation,
               ' ',
               idx,
               i,
               target.CredTypes[i]);
    }
}

void print(int identation, USERNAME_TARGET_CREDENTIAL_INFO const &info, size_t idx = 0) {
    printf("%*c [%Iu] USERNAME_TARGET_CREDENTIAL_INFO.UserName %S\n", identation, ' ', idx, info.UserName);
}

void print(int identation, CERT_CREDENTIAL_INFO const &info, size_t idx = 0) {
    printf("%*c [%Iu] CERT_CREDENTIAL_INFO.cbSize         %lu\n", identation, ' ', idx, info.cbSize);
    printf("%*c [%Iu] CERT_CREDENTIAL_INFO.CredentialBlob %S\n",
           identation,
           ' ',
           idx,
           info.cbSize ? hcrypt::to_hex(info.rgbHashOfCert, info.rgbHashOfCert + info.cbSize)
                             .c_str()
                       : L"");
}

void print(int identation, BINARY_BLOB_CREDENTIAL_INFO const &info, size_t idx = 0) {
    printf("%*c [%Iu] BINARY_BLOB_CREDENTIAL_INFO.cbBlob         %lu\n", identation, ' ', idx, info.cbBlob);
    printf("%*c [%Iu] BINARY_BLOB_CREDENTIAL_INFO.CredentialBlob %S\n",
           identation,
           ' ',
           idx,
           info.cbBlob ? hcrypt::to_hex(info.pbBlob, info.pbBlob + info.cbBlob).c_str() : L"");
}

void print_unmarshaled_buffer(int identation, CRED_MARSHAL_TYPE type, void const *buffer) {
    switch (type) {
    case CertCredential:
        print(identation, *reinterpret_cast<CERT_CREDENTIAL_INFO const *>(buffer));
        break;
    case UsernameTargetCredential:
        print(identation,
              *reinterpret_cast<USERNAME_TARGET_CREDENTIAL_INFO const *>(buffer));
        break;
    case BinaryBlobCredential:
        print(identation, *reinterpret_cast<BINARY_BLOB_CREDENTIAL_INFO const *>(buffer));
        break;
    default:
        printf("%*c unknown type %u\n", identation, ' ', type);
        break;
    }
}

void print(int identation, credman::unmarshaled_credentials const &creds) {
    print_unmarshaled_buffer(identation, creds.type, creds.buffer.get());
}

void test_enumirate_supported_persistence_types() {
    try {
        size_t idx{0};

        printf("\nEnumirating supported persistence types\n");

        credman::session_types_arr arr{credman::get_session_types()};

        std::for_each(std::cbegin(arr), std::cend(arr), [&idx](DWORD session_persistence_type) {
            printf("[%Iu] %lu, %S\n",
                   idx,
                   session_persistence_type,
                   credman::credential_session_persist_type_to_string(session_persistence_type));
            ++idx;
        });
    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_get_target_info() {
    try {
        int idx{0};

        std::wstring target_name{L"TOAD06H08-VM17.CFDEV.NTTEST.MICROSOFT.COM"};

        printf("\nQuery target info\n");

        credman::target_info_ptr info{credman::get_target_info(target_name.c_str())};

        print(0, *info);

        printf("\nQuery credentials for the target\n");

        credman::for_each(credman::get_domain_credentials(*info),
                          [&idx](CREDENTIALW const &cred) {
                              print(0, cred, idx);
                              ++idx;
                          });

        printf("\nQuery credentials\n");
        credman::credentials_carray arr{credman::get_credentials(target_name.c_str())};

        idx = 0;
        std::for_each(cbegin(arr), cend(arr), [&idx](CREDENTIALW const &creds) {
            print(idx, creds);
            ++idx;
        });

        printf("\nQuery best credentials\n");

        print(0, *credman::get_best_credentials(target_name.c_str()));

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

// test try_write_domain_credentials

void test_pack_unpack_auth_buffer(wchar_t const *user_name, wchar_t const *password) {
    try {
        printf("\nPacking credentials\n");
        printf("   user name: %S\n", user_name ? user_name : L"");
        printf("   password:  %S\n", password ? user_name : L"");

        hcrypt::buffer packed_credentials{
            credman::pack_authentication_buffer(0, user_name, password)};

        printf("   packed credentials %S\n",
               hcrypt::to_hex(packed_credentials.data(),
                              packed_credentials.data() + packed_credentials.size())
                   .c_str());

        printf("\nUnpacking credentials\n");

        credman::unpacked_credentials unpacked_creds{credman::unpack_authentication_buffer(
            0,
            reinterpret_cast<void const *>(packed_credentials.data()),
            packed_credentials.size())};

        printf("   domain:    %S\n", unpacked_creds.domain_name.c_str());
        printf("   user name: %S\n", unpacked_creds.user_name.c_str());
        printf("   password:  %S\n", unpacked_creds.password.c_str());

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_pack_unpack_auth_buffer() {
    try {
        wchar_t const *user_name = L"test_user";
        wchar_t const *domain_user_name = L"test_domain\\test_user";
        wchar_t const *password = L"test_password";

        test_pack_unpack_auth_buffer(user_name, password);

        test_pack_unpack_auth_buffer(domain_user_name, password);

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_protect_unprotect(bool as_self, std::pmr::wstring const &secret) {
    printf("\nProtecting data \"%S\" as self: %S\n", secret.c_str(), as_self ? L"yes" : L"no");

    CRED_PROTECTION_TYPE protection_type{CredUnprotected};
    std::pmr::wstring protected_secret{credman::protect(
        as_self, secret.c_str(), secret.size(), &protection_type)};

    printf("Protected data \"%S\", protection type %S\n",
           protected_secret.c_str(),
           credman::protection_type_to_string(protection_type));

    printf("is protected detected protection type %S\n",
           credman::protection_type_to_string(
               credman::get_protectection_type(protected_secret.c_str())));

    std::pmr::wstring unprotected_secret{
        credman::unprotect(as_self, secret.c_str(), secret.size())};

    printf("Unprotected data \"%S\"\n", unprotected_secret.c_str());

    BCRYPT_CODDING_ERROR_IF_NOT(secret == unprotected_secret);
}

void test_protect_unprotect() {
    try {
        std::pmr::wstring secret{L"abcdefg"};

        test_protect_unprotect(true, secret);
        test_protect_unprotect(false, secret);

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void marshal_creds(CREDENTIALW &credential) {
    try {
        printf("Marshal credentials\n");

        USERNAME_TARGET_CREDENTIAL_INFO info{0};
        info.UserName = credential.UserName;

        credman::marshaled_credentials_ptr marshaled_creds{credman::marshal_credential(info)};

        printf("  marshaled credentials: \"%S\"\n", marshaled_creds.get());

        printf("  is marshaled            %S\n",
               credman::is_marshaled_credential(marshaled_creds.get()) ? L"yes" : L"no");

        printf("Unmarshal credentials\n");

        credman::unmarshaled_credentials unmarshaled_cred{
            credman::unmarshal_credentials(marshaled_creds.get())};

        print(2, unmarshaled_cred);
        printf("   is marshaled            %S\n",
               credman::is_marshaled_credential(
                   reinterpret_cast<wchar_t const *>(unmarshaled_cred.buffer.get()))
                   ? L"yes"
                   : L"no");

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_credentials(CREDENTIALW &credential) {
    try {
        printf("\nTesting credentials\n");

        print(2, credential);

        marshal_creds(credential);

        printf("Checking if creds exist \n");

        credman::credential_ptr creds{
            credman::read_credentials(credential.TargetName, credential.Type)};

        if (creds) {
            print(2, *creds);
        } else {
            printf("  creds do not exist \n");
        }

        printf("Write creds \n");

        credman::write_credentials(&credential);

        printf("  complete\n");

        auto scoped_delete_creds{hcrypt::make_scope_guard([&credential] {
            printf("Delete creds \n");
            credman::delete_credentials(credential.TargetName, credential.Type);
            printf("Read creds \n");
            credman::credential_ptr creds{credman::read_credentials(
                credential.TargetName, credential.Type)};

            if (creds) {
                print(2, *creds);
            } else {
                printf("  creds do not exist \n");
            };
        })};

        printf("Read creds \n");

        creds = credman::read_credentials(credential.TargetName, credential.Type);

        print(2, *creds);

        printf("Write creds again\n");

        credman::write_credentials(&credential);

        printf("  complete\n");

        printf("Read creds \n");

        creds = credman::read_credentials(credential.TargetName, credential.Type);

        print(2, *creds);

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x (%u), %s\n", ex.code().value(), ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_creds_lifetime() {
    try {
        wchar_t const *target_name = L"test_target";
        wchar_t const *user_name = L"test_user_name";
        // wchar_t const *domain_user_name = L"test_domain\\test_user_name";
        wchar_t const *password = L"test_password";
        // wchar_t const *description = L"test_description";
        wchar_t const *comment = L"comment";

        CREDENTIALW credential = {0};
        credential.Flags = 0;
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = const_cast<wchar_t *>(target_name);
        credential.UserName = const_cast<wchar_t *>(user_name);
        credential.Comment = const_cast<wchar_t *>(comment);
        credential.CredentialBlobSize =
            static_cast<DWORD>((wcslen(password) + 1) * sizeof(wchar_t));
        credential.CredentialBlob =
            reinterpret_cast<LPBYTE>(const_cast<wchar_t *>(password));
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;

        test_credentials(credential);

        credential.Type = CRED_TYPE_DOMAIN_PASSWORD;
        credential.UserName = const_cast<wchar_t *>(user_name);

        test_credentials(credential);

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x (%u), %s\n", ex.code().value(), ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}

void test_enumirate_all_credentials() {
    try {
        int idx{0};

        printf("\nQuery credentials\n");
        credman::credentials_carray arr{credman::get_credentials()};

        std::for_each(cbegin(arr), cend(arr), [&idx](CREDENTIALW const &creds) {
            print(2, creds, idx);
            ++idx;
        });

    } catch (std::system_error const &ex) {
        printf("Error code = 0x%x, %s\n", ex.code().value(), ex.what());
    } catch (std::exception const &ex) {
        printf("Exception = %s\n", ex.what());
    }
}
