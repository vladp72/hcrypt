#pragma once

#include <array>
#include <map>
#include <optional>
#include <chrono>
#include <atomic>

#include "numa.hpp"

namespace perf {

    class set_this_thread_priority_t final {
    public:
        set_this_thread_priority_t(set_this_thread_priority_t const &) = delete;
        set_this_thread_priority_t(set_this_thread_priority_t &&) = delete;
        set_this_thread_priority_t &operator=(set_this_thread_priority_t const &) = delete;
        set_this_thread_priority_t &operator=(set_this_thread_priority_t &&) = delete;

        set_this_thread_priority_t()
            : prev_priority_(get_current_priority()) {
        }

        explicit set_this_thread_priority_t(int new_priority)
            : prev_priority_(get_current_priority()) {
            change_priority(new_priority);
        }

        ~set_this_thread_priority_t() {
            restore_prev_priority();
        }

        void change_priority(int new_priority) {
            if (!prev_priority_) {
                prev_priority_ = get_current_priority();
            }
            if (!SetThreadPriority(GetCurrentThread(), new_priority)) {
                throw std::system_error(
                    GetLastError(), std::system_category(), "SetThreadPriority");
            }
        }

        std::optional<int> get_prev_priority() const {
            return prev_priority_;
        }

        void restore_prev_priority() {
            if (prev_priority_) {
                change_priority(prev_priority_.value());
                prev_priority_ = std::nullopt;
            }
        }

        void arm(int prev_priority) {
            prev_priority_ = prev_priority;
        }

        void disarm() {
            prev_priority_ = std::nullopt;
        }

        explicit operator bool() const {
            return prev_priority_ != std::nullopt;
        }

    private:
        static int get_current_priority() {
            return GetThreadPriority(GetCurrentThread());
        }

        std::optional<int> prev_priority_;
    };

    class affinitize_thread_to_cpu_t final {
    public:
        affinitize_thread_to_cpu_t(affinitize_thread_to_cpu_t const &) = delete;
        affinitize_thread_to_cpu_t(affinitize_thread_to_cpu_t &&) = delete;
        affinitize_thread_to_cpu_t &operator=(affinitize_thread_to_cpu_t const &) = delete;
        affinitize_thread_to_cpu_t &operator=(affinitize_thread_to_cpu_t &&) = delete;

        enum class choose_cpu_t : char {
            no = 0,
            yes = 1,
        };

        affinitize_thread_to_cpu_t()
            : prev_affinity_(numa::cpu_info::get_thread_group_affinity()) {
        }

        explicit affinitize_thread_to_cpu_t(GROUP_AFFINITY new_affinity_group) {
            change_affinity(new_affinity_group);
        }

        explicit affinitize_thread_to_cpu_t(KAFFINITY mask) {
            change_affinity(mask);
        }

        explicit affinitize_thread_to_cpu_t(choose_cpu_t val) {
            if (val == choose_cpu_t::yes) {
                if (!choose_cpu()) {
                    throw std::system_error(
                        ERROR_CPU_SET_INVALID, std::system_category(), "Failed to automatically select CPU to run performance test");
                }
            }
        }

        ~affinitize_thread_to_cpu_t() {
            restore_prev_affinity();
        }

        [[nodiscard]] bool choose_cpu() {
            SYSTEM_CPU_SET_INFORMATION const *selected_cpu{nullptr};

            numa::cpu_info::cbuffer const cpu_info{
                numa::cpu_info::get_system_cpu_information()};

            numa::cpu_info::find_first_system_cpu_information_block(
                cpu_info,
                [&selected_cpu](SYSTEM_CPU_SET_INFORMATION const &info, size_t size) -> bool {
                    switch (info.Type) {
                    case CpuSetInformation:
                        //
                        // Stay away from any cores that are parked oe allocated to someone.
                        //
                        if (info.CpuSet.Allocated || info.CpuSet.AllocatedToTargetProcess ||
                            info.CpuSet.Parked || info.CpuSet.RealTime) {
                            return true;
                        }
                        //
                        // If we have not selected any CPUs so far then select this one
                        //
                        if (!selected_cpu) {
                            selected_cpu = &info;
                            return true;
                        }
                        //
                        // Always prefer CPU with highest efficiency class
                        //
                        if (selected_cpu->CpuSet.EfficiencyClass < info.CpuSet.EfficiencyClass) {
                            selected_cpu = &info;
                            return true;
                        }
                        //
                        // Otherwise pick CPU with highest ID that will be farthest from CPU 0
                        //
                        selected_cpu = &info;
                    }
                    return true;
                });

            if (selected_cpu) {
                //
                // Affinitize thread to the selected CPU
                //
                GROUP_AFFINITY affinity_group{1ULL << selected_cpu->CpuSet.LogicalProcessorIndex,
                                              selected_cpu->CpuSet.Group};
                change_affinity(affinity_group);
                return true;
            }
            return false;
        }

        void change_affinity(GROUP_AFFINITY const &new_affinity_group) {
            if (!prev_affinity_) {
                prev_affinity_ = numa::cpu_info::get_thread_group_affinity();
            }
            numa::cpu_info::set_thread_group_affinity(new_affinity_group);
        }

        void change_affinity(KAFFINITY mask) {
            GROUP_AFFINITY new_affinity{numa::cpu_info::get_thread_group_affinity()};
            new_affinity.Mask = mask;
            change_affinity(new_affinity);
        }

        std::optional<GROUP_AFFINITY> get_prev_affinity() const {
            return prev_affinity_;
        }

        void restore_prev_affinity() {
            if (prev_affinity_) {
                change_affinity(prev_affinity_.value());
                prev_affinity_ = std::nullopt;
            }
        }

        void arm(GROUP_AFFINITY prev_affinity) {
            prev_affinity_ = prev_affinity;
        }

        void disarm() {
            prev_affinity_ = std::nullopt;
        }

        explicit operator bool() const {
            return prev_affinity_ != std::nullopt;
        }

    private:
        std::optional<GROUP_AFFINITY> prev_affinity_{};
    };

    //
    // [.exactly L elements.)
    //
    template<size_t L>
    class fixed_size_halfopen_range {
    public:
        constexpr fixed_size_halfopen_range() = default;
        constexpr fixed_size_halfopen_range(fixed_size_halfopen_range const &) = default;
        constexpr fixed_size_halfopen_range(fixed_size_halfopen_range &&) = default;
        ~fixed_size_halfopen_range() = default;
        constexpr fixed_size_halfopen_range &operator=(fixed_size_halfopen_range const &) = default;
        constexpr fixed_size_halfopen_range &operator=(fixed_size_halfopen_range &&) = default;

        constexpr explicit fixed_size_halfopen_range(long long start)
            : start_{start} {
        }

        constexpr long long get_start() const {
            return start_;
        }

        constexpr long long get_end() const {
            return start_ + L;
        }

        constexpr long long get_length() const {
            return L;
        }

        constexpr bool is_in(unsigned long p) const {
            (p >= start_ && p < get_end());
        }

        constexpr bool is_overlapping(fixed_size_halfopen_range const &other) const {
            return is_in(other.start()) || other.is_in(start_);
        }

        constexpr bool is_before(fixed_size_halfopen_range const &other) const {
            return other.get_start() >= get_end();
        }

        constexpr bool is_after(fixed_size_halfopen_range const &other) const {
            return other.is_before(*this);
        }

        constexpr fixed_size_halfopen_range next_range() const {
            return fixed_size_halfopen_range{get_end()};
        }

        constexpr fixed_size_halfopen_range prev_range() const {
            return fixed_size_halfopen_range{start_ - L};
        }

        constexpr bool operator<(fixed_size_halfopen_range const &other) const {
            return start_ < other.start_;
        }

        constexpr bool operator<=(fixed_size_halfopen_range const &other) const {
            return start_ <= other.start_;
        }

        constexpr bool operator>(fixed_size_halfopen_range const &other) const {
            return start_ > other.start_;
        }

        constexpr bool operator>=(fixed_size_halfopen_range const &other) const {
            return start_ >= other.start_;
        }

        constexpr bool operator==(fixed_size_halfopen_range const &other) const {
            return start_ == other.start_;
        }

        constexpr bool operator!=(fixed_size_halfopen_range const &other) const {
            return start_ != other.start_;
        }

    private:
        long long start_{0LL};
    };

    enum class histogram_idx : size_t {
        percentile_1,
        percentile_2,
        percentile_3,
        percentile_4,
        percentile_5,
        percentile_6,
        percentile_7,
        percentile_8,
        percentile_9,
        percentile_10,
        percentile_25,
        percentile_50,
        percentile_75,
        percentile_90,
        percentile_95,
        percentile_96,
        percentile_97,
        percentile_98,
        percentile_99,
        percentile_99_9,
        percentile_99_99,
        percentile_99_999,
        percentile_99_9999,
        percentile_99_99999,
        percentile_size,
    };

    inline constexpr size_t const histogram_size{
        static_cast<size_t>(histogram_idx::percentile_size)};

    inline constexpr double const tail_histogram_bucket[histogram_size] = {
        1.0,  2.0,  3.0,  4.0,  5.0,   6.0,    7.0,     8.0,
        9.0,  10.0, 25.0, 50.0, 75.0,  90.0,   95.0,    96.0,
        97.0, 98.0, 99.0, 99.9, 99.99, 99.999, 99.9999, 99.99999};

    inline constexpr double const microseconds_in_second{1000'000.0};
    inline constexpr double const nanoseconds_in_second{1000'000'000.0};

    struct result_t {
        size_t calls_per_iteration{0};

        size_t bytes_processed_per_call{0};

        long long min_time{0};
        long long max_time{0};

        long long zero_samples_count{0};
        long long total_samples{0};
        long long total_time{0};
        //
        // Percentiles focusing on tail latency
        //
        long long tail_histogram_times[histogram_size];
        long long tail_histogram_count[histogram_size];
        //
        // Distribution over time if time is 100 buckets
        //
        long long frequency_histogram_count[100];
        double frequency_histogram_bucket_size{0.0};
        //
        // Mean over all samples
        //
        double mean{0.0};
        //
        // Total time spent in the middle 66% percent
        //
        long long trimmed_total_time{0};
        //
        // Number of samples in middle 66% percent
        //
        long long trimmed_total_samples{0};
        //
        // Mean after triming 10% of samples from both sides
        //
        double trimmed_mean_time{0.0};

        double sample_varience{0.0};
        double sample_standard_deviation{0.0};

        void print(int offset = 0, result_t const *baseline = nullptr) {
            printf("%*csamples                     %lli\n", offset + 2, ' ', total_samples);
            printf("%*ctrimmed samples             %lli\n", offset + 2, ' ', trimmed_total_samples);
            if (zero_samples_count) {
                printf("%*czero samples                %lli\n", offset + 2, ' ', zero_samples_count);
            }
            printf("%*ccalls per iteration         %zi\n", offset + 2, ' ', calls_per_iteration);

            if (bytes_processed_per_call) {
                printf("%*cbypes per call              %zi\n", offset + 2, ' ', bytes_processed_per_call);
            }

            double calls_microseconds{static_cast<double>(calls_per_iteration) *
                                      microseconds_in_second};

            double bytes_calls_microseconds{
                static_cast<double>(calls_per_iteration) *
                static_cast<double>(bytes_processed_per_call) * microseconds_in_second};

            double baseline_calls_microseconds{0.0};
            double baseline_bytes_calls_microseconds{0.0};

            if (baseline) {
                baseline_calls_microseconds =
                    static_cast<double>(baseline->calls_per_iteration) * microseconds_in_second;

                baseline_bytes_calls_microseconds =
                    static_cast<double>(baseline->calls_per_iteration) *
                    static_cast<double>(baseline->bytes_processed_per_call) *
                    microseconds_in_second;
            }

            {
                double average{mean / calls_microseconds};

                printf("%*cavg.sec./call               %03.10f", offset + 2, ' ', average);

                if (baseline) {
                    double other_average{baseline->mean / baseline_calls_microseconds};

                    double average_diff{average - other_average};

                    printf(" %+03.10f", average_diff);
                }
                printf("\n");
            }

            if (bytes_processed_per_call) {
                double average_per_byte{mean / bytes_calls_microseconds};

                printf("%*cavg.sec./byte               %03.10f", offset + 2, ' ', average_per_byte);

                if (baseline && baseline->bytes_processed_per_call) {
                    double other_average_per_byte{baseline->mean / baseline_bytes_calls_microseconds};

                    double average_per_byte_diff{average_per_byte - other_average_per_byte};

                    printf(" %+03.10f", average_per_byte_diff);
                }
                printf("\n");
            }

            {
                double trimmed_average{trimmed_mean_time / calls_microseconds};

                printf("%*ctrimmed avg.sec./call       %03.10f", offset + 2, ' ', trimmed_average);

                if (baseline) {
                    double other_trimmed_average{baseline->trimmed_mean_time /
                                                 baseline_calls_microseconds};

                    double trimmed_average_diff{trimmed_average - other_trimmed_average};

                    printf(" %+03.10f", trimmed_average_diff);
                }
                printf("\n");
            }

            if (bytes_processed_per_call) {
                double trimmed_average_per_byte{trimmed_mean_time / bytes_calls_microseconds};

                printf("%*ctrimmed avg.sec./byte       %03.10f", offset + 2, ' ', trimmed_average_per_byte);

                if (baseline && baseline->bytes_processed_per_call) {
                    double other_trimmed_average_per_byte{
                        baseline->trimmed_mean_time / baseline_bytes_calls_microseconds};

                    double trimmed_average_per_byte_diff{
                        trimmed_average_per_byte - other_trimmed_average_per_byte};

                    printf(" %+03.10f", trimmed_average_per_byte_diff);
                }
                printf("\n");
            }

            {
                double median{tail_histogram_times[static_cast<size_t>(histogram_idx::percentile_50)] /
                              calls_microseconds};

                printf("%*cmed.sec/call                %03.10f", offset + 2, ' ', median);

                if (baseline) {
                    double other_median{
                        baseline->tail_histogram_times[static_cast<size_t>(histogram_idx::percentile_50)] /
                        baseline_calls_microseconds};

                    double median_diff{median - other_median};

                    printf(" %+03.10f", median_diff);
                }

                printf("\n");
            }
            {
                double this_sample_standard_deviation{sample_standard_deviation / calls_microseconds};

                printf("%*cstandard daviation sec/call %03.10f", offset + 2, ' ', this_sample_standard_deviation);

                if (baseline) {
                    double other_sample_standard_deviation{
                        baseline->sample_standard_deviation / baseline_calls_microseconds};

                    double sample_standard_deviation_diff{
                        this_sample_standard_deviation - other_sample_standard_deviation};

                    printf(" %+03.10f", sample_standard_deviation_diff);
                }

                printf("\n");
            }
        }

        void print_percentiles(int offset = 0, result_t const *baseline = nullptr) {
            double calls_microseconds{static_cast<double>(calls_per_iteration) *
                                      microseconds_in_second};

            double baseline_calls_microseconds{0.0};

            if (baseline) {
                baseline_calls_microseconds =
                    static_cast<double>(baseline->calls_per_iteration) * microseconds_in_second;
            }

            for (size_t idx{static_cast<size_t>(histogram_idx::percentile_1)};
                 idx < histogram_size;
                 ++idx) {
                double bucket_time{tail_histogram_times[idx] / calls_microseconds};

                printf("%*c%08.5f %03.10f - %06lli ",
                       offset + 2,
                       ' ',
                       tail_histogram_bucket[idx],
                       bucket_time,
                       tail_histogram_count[idx]);

                if (baseline) {
                    double other_bucket_time{baseline->tail_histogram_times[idx] /
                                             baseline_calls_microseconds};

                    double bucket_time_diff{bucket_time - other_bucket_time};

                    printf(" %+014.10f ", bucket_time_diff);
                }

                printf("\n");
            }
        }

        void print_frequency(int offset = 0) {
            double calls_microseconds{static_cast<double>(calls_per_iteration) *
                                      microseconds_in_second};

            printf("%*cfrequency bucket size %03.10f\n",
                   offset + 2,
                   ' ',
                   frequency_histogram_bucket_size / microseconds_in_second);

            for (size_t idx{0}; idx < 100; ++idx) {
                if (0 == frequency_histogram_count[idx]) {
                    continue;
                }

                double bucket_time{
                    (static_cast<double>(min_time) +
                     frequency_histogram_bucket_size * static_cast<double>(idx)) /
                    microseconds_in_second};

                long long percent_of_total{100LL * frequency_histogram_count[idx] / total_samples};

                printf("%*c%03zi %03.10f - %06lli ",
                       offset + 2,
                       ' ',
                       idx,
                       bucket_time,
                       frequency_histogram_count[idx]);

                for (long long bar_idx{0}; bar_idx < percent_of_total; ++bar_idx) {
                    printf("|");
                }

                printf("\n");
            }
        }
    };

    class samples_collection {
        constexpr static long long const range_size{4000LL};

        using samples_range_t = fixed_size_halfopen_range<range_size>;
        using range_values_t = std::array<long long, range_size>;
        using samples_t = std::map<samples_range_t, range_values_t>;

    public:
        samples_collection() = default;
        ~samples_collection() = default;
        samples_collection(samples_collection const &) = default;
        samples_collection(samples_collection &&) = default;
        samples_collection &operator=(samples_collection const &) = default;
        samples_collection &operator=(samples_collection &&) = default;

        void clear() {
            min_time_ = 0;
            max_time_ = 0;
            total_samples_ = 0;
            total_time_ = 0;
            calls_per_iteration_ = 0;
            zero_samples_count_ = 0;
            samples_.clear();
        }

        template<typename F>
        bool measure(F const &f) {
            clear();
            calls_per_iteration_ = find_min_calls_per_iteration(f);
            size_t total_samples{0};

            constexpr size_t const samples_to_collect_max{10000};
            constexpr size_t const first_samples_to_collect_in_teration{1500};
            constexpr size_t const consequent_samples_to_collect_in_teration{500};

            size_t samples_to_collect_in_teration{first_samples_to_collect_in_teration};
            //
            // Keep runnig test until we got 1000 samples in the midle 66% of
            // the interval, or until we collected total 10K samples
            //
            while (total_samples < samples_to_collect_max) {
                size_t samples{0};
                while (samples < samples_to_collect_in_teration) {
                    std::chrono::microseconds time{measure(f, calls_per_iteration_)};
                    if (time >= std::chrono::microseconds{1}) {
                        add_sample(time.count());
                    } else {
                        ++zero_samples_count_;
                    }
                    ++samples;
                    ++total_samples;
                }
                //
                // In first iteration we colelcted 1500 samples
                // in all consequent iterations collect 500 samples
                //
                samples_to_collect_in_teration = consequent_samples_to_collect_in_teration;
                //
                // Calculate stats and see if we reached the
                // goal of 1000 samples in the middle 66%
                //
                result_t stats{calculate_result()};
                if (stats.trimmed_total_samples >= 1000) {
                    break;
                }
            }
            return true;
        }

        result_t calculate_result(size_t bytes_processed_per_call = 0) const noexcept {
            result_t stats{};
            bool is_first{true};

            stats.calls_per_iteration = calls_per_iteration_;
            stats.bytes_processed_per_call = bytes_processed_per_call;

            stats.min_time = min_time_;
            stats.max_time = max_time_;

            stats.zero_samples_count = zero_samples_count_;
            stats.total_samples = total_samples_;
            stats.total_time = total_time_;

            stats.mean = get_mean();

            stats.frequency_histogram_bucket_size =
                static_cast<double>(get_max_time() - get_min_time()) / 100.0;

            long long samples_count_accumulator{0};
            size_t tail_histogram_idx{static_cast<size_t>(histogram_idx::percentile_1)};

            for_each_time_bucket([&](long long time, long long count) noexcept {
                //
                // Keep accumulating how many samples we've observed so far
                //
                samples_count_accumulator += count;
                //
                // verience is mean minus sample squared. Multiply by the number
                // of samples we have in this time bucket
                //
                stats.sample_varience += count * (stats.mean - time) * (stats.mean - time);
                //
                // Frequency histogram condences entire time range samples
                // spread across to 100 slots.
                //
                double time_percent{0};
                if (get_max_time() > get_min_time()) {
                    time_percent =
                        (static_cast<double>(time - get_min_time()) /
                         static_cast<double>(get_max_time() - get_min_time())) *
                        100.0;
                }
                //
                // Agregate number of samples per slot.
                //
                stats.frequency_histogram_count[static_cast<size_t>(time_percent)] += count;
                //
                // Ratio os samples we observed so far devided by total samples
                // will give us percentile we are in.
                //
                double percentile = (static_cast<double>(samples_count_accumulator) /
                                     static_cast<double>(this->get_total_samples())) *
                                    100.0;
                //
                // Update percentile histogram. Tail histogram is an integral
                // of distribution. We need to add samples to all slots after
                // current percentile.
                //
                size_t tail_histogram_idx{static_cast<size_t>(percentile)};
                //
                // Trimmed total includes only middle 66% of samples so
                // we exclude first and last 17% of samples.
                //
                if (tail_histogram_idx >= 17 && tail_histogram_idx < 83) {
                    stats.trimmed_total_time += time * count;
                    stats.trimmed_total_samples += count;
                }
                //
                // skip all stots before current percentile
                //
                while (tail_histogram_idx < static_cast<size_t>(histogram_idx::percentile_size) &&
                       tail_histogram_bucket[tail_histogram_idx] < percentile) {
                    ++tail_histogram_idx;
                }
                //
                // Add to all remaining percentiles
                //
                while (tail_histogram_idx < static_cast<size_t>(histogram_idx::percentile_size) &&
                       tail_histogram_bucket[tail_histogram_idx] < percentile) {
                    stats.tail_histogram_times[tail_histogram_idx] = time;
                    stats.tail_histogram_count[tail_histogram_idx] = samples_count_accumulator;
                    ++tail_histogram_idx;
                }
            });

            stats.trimmed_mean_time = static_cast<double>(stats.trimmed_total_time) /
                                      static_cast<double>(stats.trimmed_total_samples);

            stats.sample_varience /= (total_samples_ - 1);

            stats.sample_standard_deviation = sqrt(stats.sample_varience);

            return stats;
        }

    private:
        bool add_sample(long long time) {
            if (time <= 0) {
                return false;
            }
            auto &samples_array = samples_[samples_range_t{value_to_range(time)}];
            samples_array[value_to_offset(time)] += 1;
            total_samples_ += 1;
            total_time_ += time;
            if (min_time_ > time || min_time_ == 0) {
                min_time_ = time;
            }
            if (max_time_ < time) {
                max_time_ = time;
            }
            return true;
        }

        //
        // Selected arbitrary to leave some space for left tail of distribution.
        //
        constexpr static inline long long const distribution_lower_bound{100LL};
        //
        // Magic number.Soume source tell that this is min number of samples
        // that should be used in an experiment
        //
        constexpr static inline size_t const min_iterations_count{32};

        //
        // We are trying to select number of calles that we will make in
        // one measure such that lower boung of our distribution will be
        // above 100 microseconds.
        //
        // Found min number of iterations have to give stable result
        // during 30 consequative runs.
        //
        // For now this is a brute force search, In future we can get
        // some improvements that
        //
        template<typename F>
        size_t find_min_calls_per_iteration(F const &f) {
            size_t iteration_count{0};
            size_t repro_count{0};
            std::chrono::microseconds cur_mu{0LL};
            while (repro_count < min_iterations_count) {
                cur_mu = measure(f, iteration_count);
                if (cur_mu >= std::chrono::microseconds{distribution_lower_bound}) {
                    ++repro_count;
                } else {
                    ++iteration_count;
                    repro_count = 0;
                }
            }
            return iteration_count;
        }
        //
        //
        //
        template<typename F>
        std::chrono::microseconds measure(F const &f, size_t calls_per_iteration) {
            auto start_time = std::chrono::high_resolution_clock::now();
            for (size_t iter = 0; iter < calls_per_iteration; ++iter) {
                //
                // Add attomics to supress CPU and compiler optimizations
                //
                std::atomic_thread_fence(std::memory_order_seq_cst);
                f();
                std::atomic_thread_fence(std::memory_order_seq_cst);
            }
            auto end_time = std::chrono::high_resolution_clock::now();
            return std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        }

        std::optional<long long> sample_count(long long time) const noexcept {
            auto const iter{samples_.find(samples_range_t{value_to_range(time)})};
            if (iter != samples_.end()) {
                return iter->second[value_to_offset(time)];
            }
            return std::nullopt;
        }

        size_t calls_per_iteration() const {
            return calls_per_iteration_;
        }

        long long get_total_samples() const noexcept {
            return total_samples_;
        }

        long long get_total_time() const noexcept {
            return total_time_;
        }

        double get_mean() const noexcept {
            return total_samples_ ? (static_cast<double>(total_time_) /
                                     static_cast<double>(total_samples_))
                                  : 0.0;
        }

        long long get_min_time() const {
            return min_time_;
        }

        std::optional<long long> get_min_time_samples_count() const noexcept {
            return sample_count(min_time_);
        }

        long long get_max_time() const noexcept {
            return max_time_;
        }

        std::optional<long long> get_max_time_samples_count() const noexcept {
            return sample_count(max_time_);
        }

        template<typename F>
        void for_each_time_bucket(F &&f) noexcept(
            noexcept(f(std::declval<long long>(), std::declval<long long>()))) {
            for (auto const &[range, samples_array] : this->samples_) {
                for (size_t idx = 0; idx < range_size; ++idx) {
                    if (samples_array[idx] > 0) {
                        f(range.get_start() + idx, samples_array[idx]);
                    }
                }
            }
        }

        template<typename F>
        void for_each_time_bucket(F &&f) const
            noexcept(noexcept(f(std::declval<long long>(), std::declval<long long>()))) {
            for (auto const &[range, samples_array] : this->samples_) {
                for (size_t idx = 0; idx < range_size; ++idx) {
                    if (samples_array[idx] > 0) {
                        f(range.get_start() + idx, samples_array[idx]);
                    }
                }
            }
        }

        template<typename F>
        void find_first_sample(F &&f) noexcept(noexcept(f(std::declval<long long>(),
                                                          std::declval<long long>()))) {
            for (auto const &[range, samples_array] : this->samples_) {
                for (size_t idx = 0; idx < range_size; ++idx) {
                    if (samples_array[idx] > 0) {
                        if (!f(range.get_start() + idx, samples_array[idx])) {
                            return;
                        }
                    }
                }
            }
        }

        template<typename F>
        void find_first_sample(F &&f) const
            noexcept(noexcept(f(std::declval<long long>(), std::declval<long long>()))) {
            for (auto const &[range, samples_array] : this->samples_) {
                for (size_t idx = 0; idx < range_size; ++idx) {
                    if (samples_array[idx] > 0) {
                        if (!f(range.get_start() + idx, samples_array[idx])) {
                            return;
                        }
                    }
                }
            }
        }

        static constexpr samples_range_t value_to_range(long long const value) {
            return samples_range_t{(value / range_size) * range_size};
        }

        static constexpr size_t value_to_offset(long long const value) {
            return static_cast<size_t>(value % range_size);
        }

        size_t calls_per_iteration_{0};
        long long min_time_{0};
        long long max_time_{0};
        long long zero_samples_count_{0};
        long long total_samples_{0};
        long long total_time_{0};
        samples_t samples_;
    };

} // namespace perf