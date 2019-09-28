#include "hbcrypt_test_dh_oakley.hpp"

namespace {

    unsigned char const OakleyGroup1P[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
        0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
        0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
        0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
        0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
        0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
        0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
        0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    unsigned char const OakleyGroup1G[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

    unsigned char const rgbrgbTlsSeed[] = {
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65,
        0x66, 0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67,
        0x68, 0x69, 0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b, 0x69,
        0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e, 0x66, 0x67, 0x68, 0x69, 0x67,
        0x68, 0x69, 0x6a, 0x68, 0x69, 0x6f, 0x70, 0x6e, 0x6f};

    wchar_t const Label[] = L"MyTlsLabel";

    unsigned long key_length = 768; // bits

} // namespace

void tesh_dh_oakley() {
    try {
        int offset{0};

        printf("\n---Test DH Oakley---------------\n");

        offset += 2;

        printf("\n%*cPreparing DH algorithm parameters, OakleyGroup1P size "
               "%zu, OakleyGroup1G size %zu\n",
               offset,
               ' ',
               sizeof(OakleyGroup1P),
               sizeof(OakleyGroup1G));

        hcrypt::buffer dh_param_buffer;
        dh_param_buffer.resize(sizeof(BCRYPT_DH_PARAMETER_HEADER) +
                               sizeof(OakleyGroup1G) + sizeof(OakleyGroup1P));

        char *buffer_cur{dh_param_buffer.data()};
        BCRYPT_DH_PARAMETER_HEADER *dh_param =
            reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER *>(buffer_cur);

        dh_param->cbLength = static_cast<unsigned long>(dh_param_buffer.size());
        dh_param->cbKeyLength = key_length / 8; // bytes
        dh_param->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

        buffer_cur += sizeof(BCRYPT_DH_PARAMETER_HEADER);
        //
        // Set prime
        //
        memcpy(buffer_cur, OakleyGroup1P, sizeof(OakleyGroup1P));

        buffer_cur += sizeof(OakleyGroup1P);
        //
        // Set generator
        //
        memcpy(buffer_cur, OakleyGroup1G, sizeof(OakleyGroup1G));

        printf("\n%*cCreating algorithm providers: %S\n", offset, ' ', BCRYPT_DH_ALGORITHM);

        bcrypt::algorithm_provider alg_a{BCRYPT_DH_ALGORITHM};
        print_object_properties(offset + 2, alg_a, true);

        bcrypt::algorithm_provider alg_b{BCRYPT_DH_ALGORITHM};

        printf("\n%*cCreating KeyA\n", offset, ' ');

        bcrypt::key key_a{alg_a.generate_empty_key_pair(key_length)};
        key_a.set_dh_parameters(dh_param, dh_param_buffer.size());
        key_a.finalize_key_pair();

        print_object_properties(offset + 2, key_a, true);

        printf("%*cExporting public KeyA\n", offset, ' ');

        hcrypt::buffer key_a_buffer{key_a.export_key(BCRYPT_DH_PUBLIC_BLOB)};

        printf("%*cPublic KeyA: %S\n", offset, ' ', hcrypt::to_hex(key_a_buffer).c_str());

        printf("\n%*cCreating KeyB\n", offset, ' ');

        bcrypt::key key_b{alg_b.generate_empty_key_pair(key_length)};
        key_b.set_dh_parameters(dh_param, dh_param_buffer.size());
        key_b.finalize_key_pair();

        print_object_properties(offset + 2, key_b, true);

        printf("%*cExporting public KeyB\n", offset, ' ');

        hcrypt::buffer key_b_buffer{key_b.export_key(BCRYPT_DH_PUBLIC_BLOB)};

        printf("%*cPublic KeyB: %S\n", offset, ' ', hcrypt::to_hex(key_b_buffer).c_str());

        printf("\n%*cProvider A importing public KeyB\n", offset, ' ');

        bcrypt::key public_key_b{alg_a.import_key_pair(
            BCRYPT_DH_PUBLIC_BLOB, key_b_buffer.data(), key_b_buffer.size())};

        print_object_properties(offset + 2, public_key_b, true);

        printf("\n%*cProvider B importing public KeyA\n", offset, ' ');

        bcrypt::key public_key_a{alg_a.import_key_pair(
            BCRYPT_DH_PUBLIC_BLOB, key_a_buffer.data(), key_a_buffer.size())};

        print_object_properties(offset + 2, public_key_a, true);

        // specify hash algorithm, SHA1 if null

        DWORD const BufferLength{2};
        BCryptBuffer BufferArray[BufferLength] = {};

        // specify secret to append
        BufferArray[0].BufferType = KDF_TLS_PRF_SEED;
        BufferArray[0].cbBuffer = sizeof(rgbrgbTlsSeed);
        BufferArray[0].pvBuffer = (PVOID) rgbrgbTlsSeed;

        // specify secret to prepend
        BufferArray[1].BufferType = KDF_TLS_PRF_LABEL;
        BufferArray[1].cbBuffer = (DWORD)((wcslen(Label) + 1) * sizeof(WCHAR));
        BufferArray[1].pvBuffer = (PVOID) Label;

        BCryptBufferDesc ParameterList{};
        ParameterList.cBuffers = 2;
        ParameterList.pBuffers = BufferArray;
        ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

        printf("\n%*cCreaating secret agreement using privake KeyA and public "
               "KeyB\n",
               offset,
               ' ');

        bcrypt::secret secret_a{bcrypt::create_secret(key_a, public_key_b)};

        print_object_properties(offset + 2, secret_a, true);

        printf("%*cCreating key using %S from shared secret\n", offset, ' ', BCRYPT_KDF_TLS_PRF);

        hcrypt::buffer agreed_key_a_buffer{
            secret_a.derive_key(BCRYPT_KDF_TLS_PRF, &ParameterList)};

        printf(
            "%*cKey: %S\n", offset + 2, ' ', hcrypt::to_hex(agreed_key_a_buffer).c_str());

        printf("\n%*cCreaating secret agreement using privake KeyB and public "
               "KeyA\n",
               offset,
               ' ');

        bcrypt::secret secret_b{bcrypt::create_secret(key_b, public_key_a)};

        print_object_properties(offset + 2, secret_b, true);

        printf("%*cCreating key using %S from shared secret\n", offset, ' ', BCRYPT_KDF_TLS_PRF);

        hcrypt::buffer agreed_key_b_buffer{
            secret_b.derive_key(BCRYPT_KDF_TLS_PRF, &ParameterList)};

        printf(
            "%*cKey: %S\n", offset + 2, ' ', hcrypt::to_hex(agreed_key_b_buffer).c_str());

        printf("\n%*cComparing keys\n", offset, ' ');

        BCRYPT_CODDING_ERROR_IF_NOT(agreed_key_a_buffer == agreed_key_b_buffer);

    } catch (std::system_error const &ex) {
        printf("test_dh_oakley, error code = 0x%x, %s, %s\n",
               ex.code().value(),
               hcrypt::status_to_string(ex.code().value()),
               ex.what());
    }
    printf("\n----------------\n");
}
