#include "hbcrypt_perf_hash.hpp"
#include <algorithm>
#include <numeric>
#include "perf\hcrypt_perf.hpp"

namespace {

    wchar_t const *hash_algorithms[]{BCRYPT_MD2_ALGORITHM,
                                     BCRYPT_MD4_ALGORITHM,
                                     BCRYPT_MD5_ALGORITHM,
                                     BCRYPT_SHA1_ALGORITHM,
                                     BCRYPT_SHA256_ALGORITHM,
                                     BCRYPT_SHA384_ALGORITHM,
                                     BCRYPT_SHA512_ALGORITHM};

    size_t const buffer_sizes[]{
        64, 128, 256, 512, 1'024, 4'096, 8'192, 16'384, 32'768, 65'536, 131'072, 262'144, 524'288, 1'048'576};

    void perf_sample_hash_create(wchar_t const *algorithm_name,
                                 hcrypt::buffer const &data_to_hash) {
        bcrypt::algorithm_provider provider{algorithm_name};
        bcrypt::hash h{provider.create_hash()};
        h.hash_data(data_to_hash.data(), data_to_hash.size());
        hcrypt::buffer hash_value{h.finish()};
    }

    void perf_sample_hash_duplicate(bcrypt::hash &hash, hcrypt::buffer const &data_to_hash) {
        bcrypt::hash h{hash};
        h.hash_data(data_to_hash.data(), data_to_hash.size());
        hcrypt::buffer hash_value{h.finish()};
    }
} // namespace

void perf_compare_hash() {
    try {
        int offset{0};

        printf("---perf_compare_hash---------------\n");

        hcrypt::buffer data_to_hash;
        data_to_hash.resize(1024);
        bcrypt::generate_random(data_to_hash.data(), data_to_hash.size());

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
        printf("\n%*cWarming up using %S.\n", offset + 2, ' ', BCRYPT_SHA1_ALGORITHM);
        perf::samples_collection warm_up_samples;
        warm_up_samples.measure([&data_to_hash]() {
            perf_sample_hash_create(BCRYPT_SHA1_ALGORITHM, data_to_hash);
        });
        perf::result_t warm_up_samples_result{
            warm_up_samples.calculate_result(data_to_hash.size())};
        warm_up_samples_result.print(offset + 2, nullptr);
        //
        // Reading buffer and accumulating result in a local variable
        // that is likley to be cached in a register
        // is a cheapest computation similar to hashing
        //
        printf("\n%*cstd::accumulate.\n", offset + 2, ' ');
        perf::samples_collection accumulate_samples;
        long long sum{0};
        accumulate_samples.measure([&data_to_hash, &sum]() {
            sum = std::accumulate(data_to_hash.begin(), data_to_hash.end(), 0);
        });
        perf::result_t accumulate_result{
            accumulate_samples.calculate_result(data_to_hash.size())};
        accumulate_result.print(offset + 2, &warm_up_samples_result);
        //
        // Copying from one buffer to another is a bit more expensive
        //
        printf("\n%*cstd::copy.\n", offset + 2, ' ');
        perf::samples_collection copy_samples;
        hcrypt::buffer other_buffer;
        other_buffer.resize(data_to_hash.size());
        copy_samples.measure([&data_to_hash, &other_buffer]() {
            std::copy(data_to_hash.begin(), data_to_hash.end(), other_buffer.begin());
        });
        perf::result_t copy_result{copy_samples.calculate_result(data_to_hash.size())};
        copy_result.print(offset + 2, &warm_up_samples_result);

        std::for_each(
            std::begin(hash_algorithms),
            std::end(hash_algorithms),
            [offset, &data_to_hash, &warm_up_samples_result](wchar_t const *algorithm_name) {
                // printf("\n%*cMeasuring perf for %S creating hash.\n", offset + 2, ' ', algorithm_name);
                // try {
                //    perf::samples_collection samples;
                //    samples.measure([&data_to_hash, algorithm_name]() {
                //        perf_sample_hash_create(algorithm_name, data_to_hash);
                //    });
                //    perf::result_t result{samples.calculate_result()};
                //    result.print(offset + 2);
                //} catch (std::system_error const &ex) {
                //    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                //}

                printf("\n%*cMeasuring perf for %S duplicating hash.\n", offset + 2, ' ', algorithm_name);
                try {
                    bcrypt::algorithm_provider provider{algorithm_name};
                    bcrypt::hash h{provider.create_hash()};

                    perf::samples_collection samples;

                    samples.measure([&data_to_hash, &h]() {
                        perf_sample_hash_duplicate(h, data_to_hash);
                    });
                    perf::result_t result{samples.calculate_result(data_to_hash.size())};
                    result.print(offset + 2, &warm_up_samples_result);
                } catch (std::system_error const &ex) {
                    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                }
            });

    } catch (std::system_error const &ex) {
        printf("perf_compare_hash, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("\n----------------\n");
}

void perf_hash_compare_buffer_sizes(wchar_t const *algorithm_name) {
    try {
        int offset{0};

        printf("---perf_hash_compare_buffer_sizes(%S)---------------\n", algorithm_name);

        hcrypt::buffer data_to_hash;
        data_to_hash.resize(1024);
        bcrypt::generate_random(data_to_hash.data(), data_to_hash.size());

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
        printf("\n%*cWarming up using %S.\n", offset + 2, ' ', algorithm_name);
        perf::samples_collection warm_up_samples;
        warm_up_samples.measure([&data_to_hash, algorithm_name]() {
            perf_sample_hash_create(algorithm_name, data_to_hash);
        });
        perf::result_t warm_up_samples_result{
            warm_up_samples.calculate_result(data_to_hash.size())};
        warm_up_samples_result.print(offset + 2);
        warm_up_samples_result.print_frequency(offset + 2);

        std::for_each(
            std::begin(buffer_sizes),
            std::end(buffer_sizes),
            [offset, &data_to_hash, &warm_up_samples_result, algorithm_name](size_t buffer_size) {
                printf("\n%*cMeasuring perf for %S buffer size %zi.\n", offset + 2, ' ', algorithm_name, buffer_size);
                try {
                    data_to_hash.resize(buffer_size);
                    bcrypt::generate_random(data_to_hash.data(), data_to_hash.size());

                    bcrypt::algorithm_provider provider{algorithm_name};
                    bcrypt::hash h{provider.create_hash()};

                    perf::samples_collection samples;

                    samples.measure([&data_to_hash, &h]() {
                        perf_sample_hash_duplicate(h, data_to_hash);
                    });
                    perf::result_t result{samples.calculate_result(data_to_hash.size())};
                    result.print(offset + 2, &warm_up_samples_result);
                    result.print_frequency(offset + 2, &warm_up_samples_result);
                } catch (std::system_error const &ex) {
                    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                }
            });

    } catch (std::system_error const &ex) {
        printf("perf_hash_compare_buffer_sizes, error code = 0x%x, %s\n",
               ex.code().value(),
               ex.what());
    }
    printf("\n----------------\n");
}