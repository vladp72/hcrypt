#pragma once

#include <array>
#include <map>
#include <optional>
#include <chrono>
#include <atomic>

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
            } else {
                throw std::system_error(
                    GetLastError(), std::system_category(), "Call to GetThreadPriority to restore thread priority failed");
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

    class affinitize_thread_to_cpu_t {
    public:
        affinitize_thread_to_cpu_t(affinitize_thread_to_cpu_t const &) = delete;
        affinitize_thread_to_cpu_t(affinitize_thread_to_cpu_t &&) = delete;
        affinitize_thread_to_cpu_t &operator=(affinitize_thread_to_cpu_t const &) = delete;
        affinitize_thread_to_cpu_t &operator=(affinitize_thread_to_cpu_t &&) = delete;

        //affinitize_thread_to_cpu_t()
        //    : prev_priority_(get_current_priority()) {
        //}

        //explicit affinitize_thread_to_cpu_t(int new_priority)
        //    : prev_priority_(get_current_priority()) {
        //    change_priority(new_priority);
        //}

        //~affinitize_thread_to_cpu_t() {
        //    restore_prev_priority();
        //}

    private:

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

    struct result_t {
        size_t calls_per_iteration{0};

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
        // Distribution over 100 buckets
        //
        long long frequency_histogram_times[100];
        long long frequency_histogram_count[100];
        //
        // Mean over all samples
        //
        double mean{0.0};
        //
        // Mean after triming 10% of samples from both sides
        //
        double trimmed_mean{0.0};

        double sample_varience{0.0};
        double sample_standard_deviation{0.0};

        void print(int offset = 0, bool print_percentile = false) {
            printf("%*csamples %lli\n", offset + 2, ' ', total_samples);
            if (zero_samples_count) {
                printf("%*czero samples %lli\n", offset + 2, ' ', zero_samples_count);
            }
            printf("%*ccalls per iteration %zi\n", offset + 2, ' ', calls_per_iteration);
            printf("%*cavg. %03.6f\n", offset + 2, ' ', mean / 1000'000.0);
            printf("%*ctrimmed avg. %03.6f\n", offset + 2, ' ', trimmed_mean / 1000'000.0);
            printf("%*cmedian. %03.6f\n",
                   offset + 2,
                   ' ',
                   tail_histogram_times[static_cast<size_t>(histogram_idx::percentile_50)] /
                       1000'000.0);

            printf("%*cstandard daviation. %03.6f\n", offset + 2, ' ', sample_standard_deviation / 1000'000.0);

            if (print_percentile) {
                for (size_t idx{static_cast<size_t>(histogram_idx::percentile_1)};
                     idx < histogram_size;
                     ++idx) {
                    printf("%*c%02.5f %03.6f - %lli\n",
                           offset + 2,
                           ' ',
                           tail_histogram_bucket[idx],
                           tail_histogram_times[idx] / 1000'000.0,
                           tail_histogram_count[idx]);
                }
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
            size_t iteraction{0};
            while (iteraction < 10000) {
                std::chrono::microseconds time{measure(f, calls_per_iteration_)};
                if (time >= std::chrono::microseconds{1}) {
                    add_sample(time.count());
                } else {
                    ++zero_samples_count_;
                }
                ++iteraction;
            }
            return true;
        }

        result_t calculate_result() const noexcept {
            result_t stats{};
            bool is_first{true};

            stats.calls_per_iteration = calls_per_iteration_;

            stats.min_time = min_time_;
            stats.max_time = max_time_;

            stats.zero_samples_count = zero_samples_count_;
            stats.total_samples = total_samples_;
            stats.total_time = total_time_;

            stats.mean = get_mean();

            long long samples_count_accumulator{0};
            size_t tail_histogram_idx{static_cast<size_t>(histogram_idx::percentile_1)};

            long long trimmed_total_time{0};
            long long trimmed_total_samples{0};

            for_each_sample([&](long long time, long long count) noexcept {
                samples_count_accumulator += count;

                stats.sample_varience +=
                    count * count * (stats.mean - time) * (stats.mean - time);

                double percentile = (static_cast<double>(samples_count_accumulator) /
                                     static_cast<double>(this->get_total_samples())) *
                                    100.0;

                size_t histogram_idx{static_cast<size_t>(percentile)};
                if (histogram_idx < 100) {
                    stats.frequency_histogram_count[static_cast<size_t>(percentile)] += count;
                    stats.frequency_histogram_times[static_cast<size_t>(percentile)] += time;

                    if (histogram_idx >= 10 && histogram_idx < 90) {
                        trimmed_total_time += time * count;
                        trimmed_total_samples += count;
                    }
                }

                while (tail_histogram_idx < static_cast<size_t>(histogram_idx::percentile_size) &&
                       tail_histogram_bucket[tail_histogram_idx] <= percentile) {
                    stats.tail_histogram_times[tail_histogram_idx] = time;
                    stats.tail_histogram_count[tail_histogram_idx] = samples_count_accumulator;
                    ++tail_histogram_idx;
                }
            });

            stats.trimmed_mean = static_cast<double>(trimmed_total_time) /
                                 static_cast<double>(trimmed_total_samples);

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
        void for_each_sample(F &&f) noexcept(noexcept(f(std::declval<long long>(),
                                                        std::declval<long long>()))) {
            for (auto const &[range, samples_array] : this->samples_) {
                for (size_t idx = 0; idx < range_size; ++idx) {
                    if (samples_array[idx] > 0) {
                        f(range.get_start() + idx, samples_array[idx]);
                    }
                }
            }
        }

        template<typename F>
        void for_each_sample(F &&f) const
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