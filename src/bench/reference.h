/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace reference {
inline uint32_t mix(uint32_t x) {
    x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; x *= 0x846ca68bU; return x ^ (x >> 16);
}
inline float input(size_t index, uint32_t seed) {
    // Normal, non-grid inputs with signs and a modest range of magnitudes.
    uint32_t x = mix(uint32_t(index) ^ seed);
    float value = float(x >> 8) * (1.0f / 8388608.0f) - 1.0f;
    return std::ldexp(value, int((x >> 3) % 7) - 3);
}
inline std::vector<size_t> coordinates(int m, int n) {
    size_t count = size_t(m) * n;
    std::vector<size_t> result;
    if (count <= 65536) {
        for (size_t i = 0; i < count; ++i) result.push_back(i);
    } else {
        result = {0, size_t(m-1), count-size_t(m), count-1, count/2};
        for (uint32_t i = 0; i < 1024; ++i) result.push_back(mix(i ^ 0x2704) % count);
        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
    }
    return result;
}
struct Error {
    size_t checked=0, failed=0, nonfinite=0;
    double max_absolute=0, error_squared=0, reference_squared=0;
    double nrmse() const { return std::sqrt(error_squared / std::max(1.0, reference_squared)); }
};
inline Error validate(const std::vector<float>& a, const std::vector<float>& b,
                      const std::vector<float>& c, int m, int n, int k, bool tf32) {
    Error result;
    for (float v : c) if (!std::isfinite(v)) ++result.nonfinite;
    for (size_t index : coordinates(m, n)) {
        size_t row = index % m, col = index / m;
        double value = 0, sum_abs = 0;
        for (int p = 0; p < k; ++p) {
            double product = double(a[row + size_t(p)*m]) * b[p + col*k];
            value += product; sum_abs += std::abs(product);
        }
        double error = std::abs(double(c[index]) - value);
        // FP32 accumulation bound; TF32 additionally budgets input rounding.
        double bound = 2e-6 + (2.0*k*0x1p-24 + (tf32 ? 0.002 : 0.000004))*sum_abs;
        if (!std::isfinite(c[index]) || error > bound) ++result.failed;
        result.max_absolute = std::max(result.max_absolute, error);
        result.error_squared += error*error; result.reference_squared += value*value;
        ++result.checked;
    }
    return result;
}
inline bool pass(const Error& e, bool tf32) {
    // Also restrict aggregate error so a conservative per-dot bound is not enough.
    return !e.failed && !e.nonfinite && std::isfinite(e.nrmse()) && e.nrmse() <= (tf32 ? 0.002 : 0.00002);
}
}
