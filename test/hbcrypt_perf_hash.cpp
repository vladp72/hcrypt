#include "hbcrypt_perf_hash.hpp"
#include <algorithm>
#include "perf\hcrypt_perf.hpp"

namespace {

    wchar_t const *hash_algorithms[]{BCRYPT_MD2_ALGORITHM,
                                     BCRYPT_MD4_ALGORITHM,
                                     BCRYPT_MD5_ALGORITHM,
                                     BCRYPT_SHA1_ALGORITHM,
                                     BCRYPT_SHA256_ALGORITHM,
                                     BCRYPT_SHA384_ALGORITHM,
                                     BCRYPT_SHA512_ALGORITHM};

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

        hcrypt::buffer data_to_hash;
        data_to_hash.resize(4 * 1024);
        bcrypt::generate_random(data_to_hash.data(), data_to_hash.size());

        //
        // To reduce verience boost priority
        //
        printf("\n%*cBoosting priority to THREAD_PRIORITY_HIGHEST.\n", offset + 2, ' ');
        perf::set_this_thread_priority_t scoped_priority_boos{THREAD_PRIORITY_HIGHEST};

        //
        // Use it to warm up
        //
        printf("\n%*cWarming up.\n", offset + 2, ' ');
        perf::samples_collection warm_up_samples;
        warm_up_samples.measure([&data_to_hash]() {
            perf_sample_hash_create(BCRYPT_MD2_ALGORITHM, data_to_hash);
        });

        std::for_each(
            std::begin(hash_algorithms),
            std::end(hash_algorithms),
            [offset, &data_to_hash](wchar_t const *algorithm_name) {
                printf("\n%*cMeasuring perf for %S creating hash.\n", offset + 2, ' ', algorithm_name);
                try {
                    perf::samples_collection samples;
                    samples.measure([&data_to_hash, algorithm_name]() {
                        perf_sample_hash_create(algorithm_name, data_to_hash);
                    });
                    perf::result_t result{samples.calculate_result()};
                    result.print(offset + 2);
                } catch (std::system_error const &ex) {
                    printf("aborted, error code = 0x%x, %s\n", ex.code().value(), ex.what());
                }

                printf("\n%*cMeasuring perf for %S duplicating hash.\n", offset + 2, ' ', algorithm_name);
                try {
                    bcrypt::algorithm_provider provider{algorithm_name};
                    bcrypt::hash h{provider.create_hash()};

                    perf::samples_collection samples;

                    samples.measure([&data_to_hash, &h]() {
                        perf_sample_hash_duplicate(h, data_to_hash);
                    });
                    perf::result_t result{samples.calculate_result()};
                    result.print(offset + 2);
                } catch (std::system_error const &ex) {
                    printf(
                        "aborted, error code = 0x%x, %s\n",
                        ex.code().value(),
                        ex.what());
                }

            });

    } catch (std::system_error const &ex) {
        printf("perf_compare_hash, error code = 0x%x, %s\n", ex.code().value(), ex.what());
    }
    printf("\n----------------\n");
}
