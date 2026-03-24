#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ==========================================
// 1. 系统参数
// ==========================================
#define TRACE_COUNT 20000
#define NOISE_LEVEL 0.2
#define NIBBLE_MASK 0x0F
#define EVAL_STEPS  200

#define GE_DFF    6.0
#define GE_XOR2   2.5
#define GE_MUX21  2.5
#define GE_INV    0.5
#define GE_AND2   1.5
#define GE_SBOX4  24.0

const uint8_t S_box[16] = {0x7,0x4,0x9,0xc,0xb,0xa,0xd,0x8,0xf,0xe,0x1,0x6,0x0,0x3,0x2,0x5};
const uint8_t HW_LUT[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};

// ==========================================
// 2. 统计学
// ==========================================
double get_noise() {
    double u1 = (double)rand() / RAND_MAX;
    double u2 = (double)rand() / RAND_MAX;
    // 防止 u1 为 0 导致 log(0)
    if (u1 < 1e-12) u1 = 1e-12;
    return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2) * NOISE_LEVEL;
}

double calculate_pearson(double *X, double *Y, int n) {
    if (n < 2) return 0.0;
    double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;
    for (int i = 0; i < n; i++) {
        sumX += X[i];
        sumY += Y[i];
        sumXY += X[i] * Y[i];
        sumX2 += X[i] * X[i];
        sumY2 += Y[i] * Y[i];
    }
    double num = (n * sumXY - sumX * sumY);
    double den = sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));
    if (den <= 1e-12 || !isfinite(den)) return 0.0;
    double r = num / den;
    if (!isfinite(r)) return 0.0;
    return r;
}

long long predict_mtd(double rho) {
    if (isnan(rho) || !isfinite(rho) || rho <= 0.0001) return 1000000000;
    return (long long)(15.0 / (rho * rho));
}

// ==========================================
// 3. 攻击与评估核心模块
// ==========================================

double run_tvla(int protected) {
    int n = TRACE_COUNT / 2;
    if (n < 2) return 0.0;
    double sum_f = 0, sum_r = 0, sq_f = 0, sq_r = 0;
    uint8_t fixed_p = 0x5, key = 0x3;
    for (int i = 0; i < n; i++) {
        double p_f, p_r;
        if (protected) {
            uint8_t mi = rand()&0xF, mo = rand()&0xF;
            p_f = HW_LUT[S_box[fixed_p ^ key] ^ mo] + get_noise();
            p_r = HW_LUT[S_box[(rand()&0xF) ^ key] ^ mo] + get_noise();
        } else {
            p_f = HW_LUT[S_box[fixed_p ^ key]] + get_noise();
            p_r = HW_LUT[S_box[(rand()&0xF) ^ key]] + get_noise();
        }
        sum_f += p_f; sq_f += p_f * p_f;
        sum_r += p_r; sq_r += p_r * p_r;
    }
    double mf = sum_f / n, mr = sum_r / n;
    double vf = (sq_f / n) - (mf * mf);
    double vr = (sq_r / n) - (mr * mr);
    double den = sqrt((vf + vr) / n);
    if (den <= 1e-12 || !isfinite(den)) return 0.0;
    double t = (mf - mr) / den;
    return fabs(t);
}

void perform_dpa(int protected, int *mtd_out, double *max_diff_out) {
    uint8_t p_texts[TRACE_COUNT];
    double traces[TRACE_COUNT];
    uint8_t key = 0x6;
    for (int i = 0; i < TRACE_COUNT; i++) {
        p_texts[i] = rand() & 0xF;
        uint8_t val = S_box[p_texts[i] ^ key];
        if (protected) val ^= (rand() & 0xF);
        traces[i] = HW_LUT[val] + get_noise();
    }
    *mtd_out = -1;
    *max_diff_out = 0.0;
    for (int n = EVAL_STEPS; n <= TRACE_COUNT; n += EVAL_STEPS) {
        double best_diff = 0; int best_g = -1;
        for (int g = 0; g < 16; g++) {
            double g0 = 0, g1 = 0; int c0 = 0, c1 = 0;
            for (int i = 0; i < n; i++) {
                if (HW_LUT[S_box[p_texts[i] ^ g]] > 2) {
                    g1 += traces[i]; c1++;
                } else {
                    g0 += traces[i]; c0++;
                }
            }
            double d = (c0 && c1) ? fabs((g1/c1) - (g0/c0)) : 0.0;
            if (d > best_diff) { best_diff = d; best_g = g; }
            if (g == key) *max_diff_out = d;
        }
        if (best_g == key) { *mtd_out = n; break; }
    }
}

void perform_cpa(int protected, int *mtd_out, double *max_rho_out) {
    uint8_t p_texts[TRACE_COUNT];
    double traces[TRACE_COUNT];
    uint8_t key = 0x6;
    for (int i = 0; i < TRACE_COUNT; i++) {
        p_texts[i] = rand() & 0xF;
        uint8_t val = S_box[p_texts[i] ^ key];
        if (protected) val ^= (rand() & 0xF);
        traces[i] = HW_LUT[val] + get_noise();
    }
    *mtd_out = -1;
    *max_rho_out = 0.0;
    for (int n = EVAL_STEPS; n <= TRACE_COUNT; n += EVAL_STEPS) {
        double best_r = 0; int best_g = -1;
        for (int g = 0; g < 16; g++) {
            double hypo[TRACE_COUNT];
            for (int i = 0; i < n; i++) hypo[i] = HW_LUT[S_box[p_texts[i] ^ g]];
            double r = fabs(calculate_pearson(traces, hypo, n));
            if (r > best_r) { best_r = r; best_g = g; }
            if (g == key) *max_rho_out = r;
        }
        if (best_g == key) { *mtd_out = n; break; }
    }
}

void perform_2order_cpa(double *max_rho_out) {
    uint8_t p_texts[TRACE_COUNT];
    double p0[TRACE_COUNT], p1[TRACE_COUNT], combined[TRACE_COUNT], hypo[TRACE_COUNT];
    uint8_t key = 0x6;
    for (int i = 0; i < TRACE_COUNT; i++) {
        p_texts[i] = rand() & 0xF;
        uint8_t m = rand() & 0xF;
        p0[i] = HW_LUT[m] + get_noise();
        p1[i] = HW_LUT[S_box[p_texts[i] ^ key] ^ m] + get_noise();
        hypo[i] = HW_LUT[S_box[p_texts[i] ^ key]];
    }
    double m0 = 0, m1 = 0;
    for (int i = 0; i < TRACE_COUNT; i++) { m0 += p0[i]; m1 += p1[i]; }
    m0 /= TRACE_COUNT; m1 /= TRACE_COUNT;
    double sum_comb = 0, sum_comb2 = 0;
    for (int i = 0; i < TRACE_COUNT; i++) {
        combined[i] = (p0[i] - m0) * (p1[i] - m1);
        sum_comb += combined[i];
        sum_comb2 += combined[i] * combined[i];
    }
    double var = (sum_comb2 / TRACE_COUNT) - (sum_comb / TRACE_COUNT) * (sum_comb / TRACE_COUNT);
    if (var <= 1e-12) {
        *max_rho_out = 0.0;
        return;
    }
    *max_rho_out = fabs(calculate_pearson(combined, hypo, TRACE_COUNT));
}

void perform_2order_dpa(int *mtd_out, double *max_diff_out) {
    uint8_t p_texts[TRACE_COUNT];
    double p0[TRACE_COUNT], p1[TRACE_COUNT], combined[TRACE_COUNT];
    uint8_t key = 0x6;
    for (int i = 0; i < TRACE_COUNT; i++) {
        p_texts[i] = rand() & 0xF;
        uint8_t m = rand() & 0xF;
        p0[i] = HW_LUT[m] + get_noise();
        p1[i] = HW_LUT[S_box[p_texts[i] ^ key] ^ m] + get_noise();
    }
    double m0 = 0, m1 = 0;
    for (int i = 0; i < TRACE_COUNT; i++) { m0 += p0[i]; m1 += p1[i]; }
    m0 /= TRACE_COUNT; m1 /= TRACE_COUNT;
    double sum_comb = 0, sum_comb2 = 0;
    for (int i = 0; i < TRACE_COUNT; i++) {
        combined[i] = (p0[i] - m0) * (p1[i] - m1);
        sum_comb += combined[i];
        sum_comb2 += combined[i] * combined[i];
    }
    double var = (sum_comb2 / TRACE_COUNT) - (sum_comb / TRACE_COUNT) * (sum_comb / TRACE_COUNT);
    // 若方差过小，直接返回 -1 和 0，避免 NaN
    if (var <= 1e-12) {
        *mtd_out = -1;
        *max_diff_out = 0.0;
        return;
    }

    *mtd_out = -1;
    *max_diff_out = 0.0;
    for (int n = EVAL_STEPS; n <= TRACE_COUNT; n += EVAL_STEPS) {
        double best_diff = 0; int best_g = -1;
        for (int g = 0; g < 16; g++) {
            double g0 = 0, g1 = 0; int c0 = 0, c1 = 0;
            for (int i = 0; i < n; i++) {
                if (HW_LUT[S_box[p_texts[i] ^ g]] > 2) {
                    g1 += combined[i]; c1++;
                } else {
                    g0 += combined[i]; c0++;
                }
            }
            double d = (c0 && c1) ? fabs((g1/c1) - (g0/c0)) : 0.0;
            if (d > best_diff) { best_diff = d; best_g = g; }
            if (g == key) *max_diff_out = d;
        }
        if (best_g == key) { *mtd_out = n; break; }
    }
}

// ==========================================
// 4. 评估结构体定义
// ==========================================
typedef struct {
    double area_ge;
    int ram_bits;
    int cycles;
    double rho_max;
    long long mtd_pred;
    double tvla_t;
    int mtd_dpa;
    double max_diff;
    int mtd_cpa;
} SchemeEval;

// ==========================================
// 5. 硬件资源算账模块
// ==========================================
void calculate_area(int protected, double *ge_out, int *ram_out, int *cycles_out) {
    double base_area = (128 * GE_DFF) + (8 * GE_SBOX4);
    if (!protected) {
        *ge_out = base_area;
        *ram_out = 0;
        *cycles_out = 32;
    } else {
        int extra_regs = 64 + 8 + 4;
        double logic = (16 * GE_XOR2) + 120.0;
        *ge_out = base_area + (extra_regs * GE_DFF) + logic;
        *ram_out = 64;
        *cycles_out = 48;
    }
}

void evaluate_unprotected(SchemeEval *m) {
    calculate_area(0, &m->area_ge, &m->ram_bits, &m->cycles);
    m->tvla_t = run_tvla(0);
    perform_dpa(0, &m->mtd_dpa, &m->max_diff);
    perform_cpa(0, &m->mtd_cpa, &m->rho_max);
    m->mtd_pred = predict_mtd(m->rho_max);
}

void evaluate_masked(SchemeEval *m) {
    calculate_area(1, &m->area_ge, &m->ram_bits, &m->cycles);
    m->tvla_t = run_tvla(1);
    perform_dpa(1, &m->mtd_dpa, &m->max_diff);
    perform_cpa(1, &m->mtd_cpa, &m->rho_max);
    m->mtd_pred = predict_mtd(m->rho_max);
}

void print_report(SchemeEval *u, SchemeEval *m) {
    printf("\n"
    "===============================================================\n"
    "      UBLOCK PROTECTION EVALUATION REPORT (V2.0-Scientific)    \n"
    "===============================================================\n");
    printf("%-20s | %-12s | %-12s\n", "Metric", "Unprotected", "Dynamic Table");
    printf("---------------------------------------------------------------\n");
    printf("%-20s | %-12.1f | %-12.1f\n", "Area (GEs)", u->area_ge, m->area_ge);
    printf("%-20s | %-12d | %-12d\n", "RAM (Extra bits)", u->ram_bits, m->ram_bits);
    printf("%-20s | %-12d | %-12d\n", "Latency (Cycles)", u->cycles, m->cycles);
    printf("%-20s | %-12.4f | %-12.4f\n", "Max Correlation", u->rho_max, m->rho_max);
    printf("%-20s | %-12.2f | %-12.2f\n", "TVLA T-statistic", u->tvla_t, m->tvla_t);
    printf("%-20s | %-12d | %-12d\n", "DPA MTD", u->mtd_dpa, m->mtd_dpa);
    printf("%-20s | %-12d | %-12d\n", "CPA MTD", u->mtd_cpa, m->mtd_cpa);
    printf("---------------------------------------------------------------\n");
    printf("%-20s | %-12lld | %-12lld\n", "Predicted MTD", u->mtd_pred, m->mtd_pred);
    printf("===============================================================\n");

    printf("\nDetailed Analysis:\n");
    printf("1. Resource: Protected version overhead is %.1f GE (%.1fx Area).\n",
            m->area_ge - u->area_ge, m->area_ge / u->area_ge);
    printf("2. Efficiency: Extra RAM is exactly %d bits (16 nibbles), matching UBLOCK requirements.\n", m->ram_bits);
    if (u->mtd_pred > 0 && m->mtd_pred > 0) {
        printf("3. Safety: The security gain (MTD ratio) is approximately %.0f times.\n",
                (double)m->mtd_pred / u->mtd_pred);
    } else {
        printf("3. Safety: Unprotected MTD=%d, Protected MTD=%d => strong protection.\n", u->mtd_dpa, m->mtd_dpa);
    }
}

int main() {
    srand((unsigned)time(NULL));
    SchemeEval unprot, masked;

    evaluate_unprotected(&unprot);
    evaluate_masked(&masked);

    print_report(&unprot, &masked);

    double rho2;
    perform_2order_cpa(&rho2);
    int mtd2_dpa;
    double max_diff2;
    perform_2order_dpa(&mtd2_dpa, &max_diff2);

    printf("\n--- High-Order Security Test ---\n");
    printf(" [2nd-CPA ] Correlation: %.4f, Predicted MTD: %lld\n", rho2, predict_mtd(rho2));
    printf(" [2nd-DPA ] MTD: %d, Max Diff: %.4f\n", mtd2_dpa, max_diff2);

    // 正确的二阶安全判断逻辑
    int is_vuln = 0;
    if (isfinite(rho2) && rho2 > 0.05) is_vuln = 1;
    if (mtd2_dpa > 0 && mtd2_dpa < TRACE_COUNT) is_vuln = 1;
    printf(" [Status  ] %s\n", is_vuln ? "VULNERABLE to 2nd-order" : "SECURE");

    return 0;
}