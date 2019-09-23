#pragma once

#include "hcrypt_common.h"
#include <ncrypt.h>

#pragma comment (lib, "ncrypt.lib")

namespace ncrypt {

    template <typename T>
    class buffer_ptr final {
    public:

        using value_type = T;
        using mutable_value_type = std::remove_const_t<T>;
        constexpr static bool is_void{ std::is_void_v<std::remove_cv_t<T>> };
        using reference_type = std::conditional_t<
                                        is_void,
                                        void, 
                                        std::add_lvalue_reference_t<T>>;
        using pointer_type = T*;
        using mutable_pointer_type = mutable_value_type*;

        buffer_ptr() noexcept = default;

        buffer_ptr(pointer_type p) noexcept
            : p_(p) {
        }

        buffer_ptr(buffer_ptr const &) noexcept = delete;
        buffer_ptr &operator= (buffer_ptr const&) noexcept = delete;

        buffer_ptr(buffer_ptr&& other) noexcept
            : p_{other.detach()} {
        }

        buffer_ptr &operator= (buffer_ptr&& other) noexcept {
            if (this != &other) {
                free();
                p_ = other.detach();
            }
            return *this;
        }

        ~buffer_ptr() noexcept {
            free();
        }

        void swap(buffer_ptr& other) noexcept {
            pointer_type p{ p_ };
            p_ = other.p_;
            other.p_ = p;
        }

        pointer_type get() const noexcept {
            return p_;
        }

        reference_type operator * () const noexcept {
            return *p_; 
        }

        pointer_type operator -> () const noexcept {
            return p_; 
        }

        void free() noexcept {
            if (p_) {
                NCryptFreeBuffer(const_cast<mutable_pointer_type>(p_));
                p_ = nullptr;
            }
        }

        [[nodiscard]]
        pointer_type detach() noexcept {
            pointer_type p{ p_ };
            p_ = nullptr;
            return p;
        }

        void attach(pointer_type p) noexcept {
            free();
            p_ = p;
        }

        explicit operator bool() const noexcept {
            return p_ != nullptr;
        }

    private:
        pointer_type p_{ nullptr };
    };

    template < typename T>
    inline void swap(buffer_ptr<T> first, buffer_ptr<T> second)  noexcept {
        first.swap(second);
    }

    using providers_cptr = buffer_ptr<NCryptProviderName const>;
    using providers_t = std::pair<providers_cptr, unsigned long>;

    [[nodiscard]]
    inline std::error_code try_enum_providers(providers_t *providers) noexcept {
        NCryptProviderName *providers_buffer{ nullptr };
        unsigned long providers_count{ 0 };
        hcrypt::status err{ NCryptEnumStorageProviders(&providers_count,
                                                       &providers_buffer,
                                                       0) };
        if (hcrypt::is_success(err)) {
            providers->first.attach(providers_buffer);
            providers->second = providers_count;
        }
        return err;
    }

    inline providers_t const enum_providers() {
        providers_t providers;
        std::error_code err{ try_enum_providers(&providers) };
        if (hcrypt::is_failure(err) ) {
            throw std::system_error(err, "NCryptEnumStorageProviders failed");
        }
        return providers;
    }

    template<typename FN>
    inline void find_first(providers_t const& providers, FN const& fn) {
        auto const& [buffer, element_count] = providers;
        for (unsigned long idx = 0; idx < element_count; ++idx) {
            if (!fn(buffer.get()[idx])) {
                break;
            }
        }
    }

}