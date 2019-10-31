#include "hbcrypt_perf_base64.hpp"
#include <algorithm>
#include <numeric>
#include "perf\hcrypt_perf.hpp"

namespace {

    size_t const buffer_sizes[]{
        64, 128, 256, 512, 1'024, 4'096, 8'192, 16'384, 32'768, 65'536, 131'072, 262'144, 524'288, 1'048'576};

    void perf_sample_base64(hcrypt::buffer const &in) {
        std::string encoded;
        encoded.reserve(hcrypt::get_base64_length(in.size()));
        hcrypt::to_base64(in.data(), in.size(), std::back_inserter(encoded));

        hcrypt::buffer decoded;
        decoded.reserve((3 * encoded.size()) / 4);

        auto [result, iter] = hcrypt::from_base64(
            encoded.data(), encoded.size(), std::back_inserter(decoded));

        BCRYPT_CODDING_ERROR_IF(false == result);
    }

    void perf_sample_binary_to_string(hcrypt::buffer const &in) {
        std::string encoded{hcrypt::binary_to_string(
            in.data(), in.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF)};
        hcrypt::buffer decoded{hcrypt::string_to_binary(encoded, CRYPT_STRING_BASE64)};
    }

} // namespace

void perf_base64_compare_buffer_sizes() {
    try {
        int offset{0};

        printf("---perf_base64_compare_buffer_sizes---------------\n");

        hcrypt::buffer data_to_encode;
        data_to_encode.resize(1024);
        bcrypt::generate_random(data_to_encode.data(), data_to_encode.size());

        //
        // To reduce verience boost priority
        //
        printf("\n%*cBoosting priority to THREAD_PRIORITY_HIGHEST.\n", offset + 2, ' ');
        perf::set_this_thread_priority_t scoped_priority_boos{THREAD_PRIORITY_HIGHEST};

        perf::affinitize_thread_to_cpu_t scoped_thread_affinity{
            perf::affinitize_thread_to_cpu_t::choose_cpu_t::yes};
        printf("\n%*cAffinitized CPU to.\n", offset + 2, ' ');
        numa::print(2, 0, numa::cpu_info::get_thread_group_affinity());

        //
        // Warm up
        //
        printf("\n%*cWarming up using hcrypt::binary_to_string - "
               "hcrypt::string_to_binary.\n",
               offset + 2,
               ' ');
        perf::samples_collection warm_up_samples;
        warm_up_samples.measure([&data_to_encode]() {
            perf_sample_binary_to_string(data_to_encode);
        });
        perf::result_t warm_up_samples_result{
            warm_up_samples.calculate_result(data_to_encode.size())};
        warm_up_samples_result.print(offset + 2);
        //warm_up_samples_result.print_frequency(offset + 2);

        std::for_each(
            std::begin(buffer_sizes),
            std::end(buffer_sizes),
            [offset, &data_to_encode, &warm_up_samples_result](size_t buffer_size) {
                printf("\n%*cMeasuring perf for hcrypt::binary_to_string - "
                       "hcrypt::string_to_binary buffer size %zi.\n",
                       offset + 2,
                       ' ',
                       buffer_size);
                try {
                    data_to_encode.resize(buffer_size);
                    bcrypt::generate_random(data_to_encode.data(),
                                            data_to_encode.size());

                    perf::samples_collection samples;

                    samples.measure([&data_to_encode]() {
                        perf_sample_binary_to_string(data_to_encode);
                    });
                    perf::result_t result{
                        samples.calculate_result(data_to_encode.size())};
                    result.print(offset + 2, &warm_up_samples_result);
                    result.print_frequency(offset + 2);
                } catch (std::system_error const &ex) {
                    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                }
            });

        std::for_each(
            std::begin(buffer_sizes),
            std::end(buffer_sizes),
            [offset, &data_to_encode, &warm_up_samples_result](size_t buffer_size) {
                printf("\n%*cMeasuring perf for hcrypt::to_base64 - "
                       "hcrypt::from_base64 buffer size %zi.\n",
                       offset + 2,
                       ' ',
                       buffer_size);
                try {
                    data_to_encode.resize(buffer_size);
                    bcrypt::generate_random(data_to_encode.data(),
                                            data_to_encode.size());

                    perf::samples_collection samples;

                    samples.measure([&data_to_encode]() {
                        perf_sample_base64(data_to_encode);
                    });
                    perf::result_t result{
                        samples.calculate_result(data_to_encode.size())};
                    result.print(offset + 2, &warm_up_samples_result);
                    result.print_frequency(offset + 2);
                } catch (std::system_error const &ex) {
                    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                }
            });

    } catch (std::system_error const &ex) {
        printf("perf_base64_compare_buffer_sizes, error code = 0x%x, %s\n",
               ex.code().value(),
               ex.what());
    }
    printf("\n----------------\n");
}