#pragma once

#include "hcrypt_test_helpers.hpp"

void perf_compare_hash();

void perf_hash_compare_buffer_sizes(wchar_t const *algorithm_name = BCRYPT_SHA1_ALGORITHM);