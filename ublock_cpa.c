#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

// UBlock CPA攻击参数
#define BLOCK_SIZE 16       // 128位分组，16字节
#define KEY_SIZE 16         // 128位密钥，16字节  
#define NUM_ROUNDS 16       // 16轮加密
#define NUM_TRACES 5000     // 功耗轨迹数量
#define TIME_POINTS 100     // 每条轨迹的时间采样点数
#define NOISE_STDDEV 1.0    // 噪声标准差
#define AFFINE_A 2.0        // 仿射系数a
#define AFFINE_B 5.0        // 仿射常数b
#define SBOX_WINDOW_START 15  // S盒操作时间窗口开始
#define SBOX_WINDOW_END 25    // S盒操作时间窗口结束

// 真实的UBlock S盒 (来自源代码)
static const unsigned char UBLOCK_SBOX[16] = {
    0x7, 0x4, 0x9, 0xc, 0xb, 0xa, 0xd, 0x8, 
    0xf, 0xe, 0x1, 0x6, 0x0, 0x3, 0x2, 0x5
};

// UBlock 轮常数 RC (来自源代码)
static const unsigned char RC[16][16] = {
    {0x9,0x8,0x8,0xc,0xc,0x9,0xd,0xd,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xf,0x0,0xe,0x4,0xa,0x1,0xb,0x5,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x2,0x1,0x3,0x5,0x7,0x0,0x6,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x8,0x3,0x9,0x7,0xd,0x2,0xc,0x6,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xc,0x7,0xd,0x3,0x9,0x6,0x8,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x4,0xf,0x5,0xb,0x1,0xe,0x0,0xa,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x5,0xe,0x4,0xa,0x0,0xf,0x1,0xb,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x7,0xc,0x6,0x8,0x2,0xd,0x3,0x9,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x3,0x9,0x2,0xd,0x6,0x8,0x7,0xc,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xb,0x3,0xa,0x7,0xe,0x2,0xf,0x6,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xa,0x7,0xb,0x3,0xf,0x6,0xe,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x8,0xe,0x9,0xa,0xd,0xf,0xc,0xb,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xd,0xc,0xc,0x8,0x8,0xd,0x9,0x9,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x7,0x8,0x6,0xc,0x2,0x9,0x3,0xd,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0x3,0x0,0x2,0x4,0x6,0x1,0x7,0x5,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0},
    {0xa,0x1,0xb,0x5,0xf,0x0,0xe,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}
};

// UBlock置换矩阵(基于源代码逻辑)
static const unsigned char A1[16] = {1,2,3,4,5,6,7,0,9,10,11,12,13,14,15,8};
static const unsigned char A2[16] = {2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9};
static const unsigned char A3[16] = {5,6,7,0,1,2,3,4,13,14,15,8,9,10,11,12};

// 线性层置换
static const unsigned char L1[16] = {2,3,6,7,8,9,12,13,0,1,4,5,14,15,10,11};
static const unsigned char L2[16] = {4,5,14,15,10,11,0,1,2,3,12,13,8,9,6,7};

// 密钥调度置换
static const unsigned char SK_PERM[16] = {0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13};
static const unsigned char KEY_PERM[16] = {6,0,8,13,1,15,5,10,4,9,12,2,11,3,7,14};

// 全局子密钥存储
unsigned char UBlock_Subkey[17][32];  // 17轮子密钥，每轮32个nibble

// 数据结构
typedef struct {
    unsigned char data[BLOCK_SIZE];
} UBlock_Block;

typedef struct {
    double trace[TIME_POINTS];
    UBlock_Block plaintext;
} UBlock_PowerTrace;

typedef struct {
    double correlation[256][TIME_POINTS];  // 每个密钥猜测在每个时间点的相关系数
    double max_correlation[256];           // 每个密钥猜测的最大相关系数
    int best_time_point[256];              // 每个密钥猜测的最佳时间点
    int best_key;
    double max_overall_correlation;
    int best_overall_time_point;
    
    // UBlock特有的分析数据
    double nibble_correlation[16][16][TIME_POINTS];  // 每个nibble位置的相关系数
    double high_nibble_correlation[256];             // 高4位的最大相关系数
    double low_nibble_correlation[256];              // 低4位的最大相关系数
} UBlock_CPAResult;

// 工具函数
int hamming_weight(unsigned char value) {
    int weight = 0;
    for (int i = 0; i < 8; i++) {
        if ((value >> i) & 1) weight++;
    }
    return weight;
}

int hamming_weight_nibble(unsigned char value) {
    int weight = 0;
    for (int i = 0; i < 4; i++) {
        if ((value >> i) & 1) weight++;
    }
    return weight;
}

// Box-Muller变换生成高斯噪声
double gaussian_noise(double mean, double stddev) {
    static int has_spare = 0;
    static double spare;
    
    if (has_spare) {
        has_spare = 0;
        return spare * stddev + mean;
    }
    
    has_spare = 1;
    
    static double u, v, mag;
    do {
        u = 2.0 * ((double)rand() / RAND_MAX) - 1.0;
        v = 2.0 * ((double)rand() / RAND_MAX) - 1.0;
        mag = u * u + v * v;
    } while (mag >= 1.0 || mag == 0.0);
    
    mag = sqrt(-2.0 * log(mag) / mag);
    spare = v * mag;
    return u * mag * stddev + mean;
}

// UBlock功耗泄漏模型
double ublock_power_model(unsigned char intermediate_value, double noise_level) {
    int hw = hamming_weight(intermediate_value);
    double leakage = AFFINE_A * hw + AFFINE_B;
    double noise = gaussian_noise(0.0, noise_level);
    return leakage + noise;
}

// 应用置换
void apply_permutation(unsigned char *state, const unsigned char *perm, int size) {
    unsigned char temp[16];
    memcpy(temp, state, size);
    for (int i = 0; i < size; i++) {
        state[i] = temp[perm[i]];
    }
}

// UBlock密钥调度(来自原代码)
void ublock_key_schedule(unsigned char *master_key) {
    unsigned char state1[16], state2[16];
    
    // 初始化：将字节转换为nibble表示
    for (int i = 0; i < 16; i++) {
        state1[i] = (master_key[i] >> 4) & 0xF;  // 高4位
        state2[i] = master_key[i] & 0xF;         // 低4位
    }
    
    // 初始重排列
    apply_permutation(state1, SK_PERM, 16);
    apply_permutation(state2, SK_PERM, 16);
    
    // 存储第0轮密钥
    memcpy(UBlock_Subkey[0], state1, 16);
    memcpy(UBlock_Subkey[0] + 16, state2, 16);
    
    // 生成轮密钥
    for (int round = 1; round <= 16; round++) {
        // 应用密钥置换
        apply_permutation(state1, KEY_PERM, 16);
        
        // 与轮常数异或
        for (int i = 0; i < 16; i++) {
            state1[i] ^= RC[round-1][i];
        }
        
        // 应用S盒
        for (int i = 0; i < 16; i++) {
            state1[i] = UBLOCK_SBOX[state1[i]];
        }
        
        // 应用SK置换
        apply_permutation(state1, SK_PERM, 16);
        
        // 与state2异或
        for (int i = 0; i < 16; i++) {
            state1[i] ^= state2[i];
        }
        
        // 更新state2
        unsigned char new_state2[16];
        apply_permutation(state1, KEY_PERM, 16);
        memcpy(new_state2, state1, 16);
        memcpy(state2, new_state2, 16);
        
        // 存储轮密钥
        memcpy(UBlock_Subkey[round], state1, 16);
        memcpy(UBlock_Subkey[round] + 16, state2, 16);
    }
}

// 计算UBlock第一轮S盒输出（CPA攻击目标）
unsigned char compute_ublock_first_sbox_output(unsigned char plaintext_byte, unsigned char key_byte) {
    // UBlock特有：分离高4位和低4位
    unsigned char pt_high = (plaintext_byte >> 4) & 0xF;
    unsigned char pt_low = plaintext_byte & 0xF;
    unsigned char key_high = (key_byte >> 4) & 0xF;
    unsigned char key_low = key_byte & 0xF;
    
    // 密钥加法后的S盒输入
    unsigned char sbox_input_high = pt_high ^ key_high;
    unsigned char sbox_input_low = pt_low ^ key_low;
    
    // UBlock S盒输出
    unsigned char sbox_output_high = UBLOCK_SBOX[sbox_input_high];
    unsigned char sbox_output_low = UBLOCK_SBOX[sbox_input_low];
    
    // 合并为字节
    return (sbox_output_high << 4) | sbox_output_low;
}

// 分别计算高4位和低4位的S盒输出
unsigned char compute_ublock_high_nibble_sbox(unsigned char plaintext_byte, unsigned char key_guess) {
    unsigned char pt_high = (plaintext_byte >> 4) & 0xF;
    unsigned char key_high = (key_guess >> 4) & 0xF;
    return UBLOCK_SBOX[pt_high ^ key_high];
}

unsigned char compute_ublock_low_nibble_sbox(unsigned char plaintext_byte, unsigned char key_guess) {
    unsigned char pt_low = plaintext_byte & 0xF;
    unsigned char key_low = key_guess & 0xF;
    return UBLOCK_SBOX[pt_low ^ key_low];
}

// 生成随机明文
void generate_random_ublock(UBlock_Block *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block->data[i] = rand() & 0xFF;
    }
}

// 生成UBlock功耗轨迹
void generate_ublock_power_trace(UBlock_PowerTrace *trace, unsigned char *key, int target_byte) {
    // 生成随机明文
    generate_random_ublock(&trace->plaintext);
    
    // 计算UBlock第一轮S盒输出
    unsigned char sbox_output = compute_ublock_first_sbox_output(
        trace->plaintext.data[target_byte], 
        key[target_byte]
    );
    
    // 生成功耗轨迹
    for (int t = 0; t < TIME_POINTS; t++) {
        if (t >= SBOX_WINDOW_START && t <= SBOX_WINDOW_END) {
            // S盒操作的时间窗口
            trace->trace[t] = ublock_power_model(sbox_output, NOISE_STDDEV);
        } else {
            // 其他操作的功耗
            unsigned char random_data = rand() & 0xFF;
            trace->trace[t] = ublock_power_model(random_data, NOISE_STDDEV * 2.0);
        }
    }
}

// 计算相关系数
double calculate_correlation(double *x, double *y, int n) {
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0, sum_y2 = 0;
    
    for (int i = 0; i < n; i++) {
        sum_x += x[i];
        sum_y += y[i];
        sum_xy += x[i] * y[i];
        sum_x2 += x[i] * x[i];
        sum_y2 += y[i] * y[i];
    }
    
    double numerator = n * sum_xy - sum_x * sum_y;
    double denominator = sqrt((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y));
    
    return (denominator == 0.0) ? 0.0 : numerator / denominator;
}

// UBlock专用CPA攻击
void perform_ublock_cpa_attack(UBlock_PowerTrace *traces, int num_traces, int target_byte, UBlock_CPAResult *result) {
    printf("开始UBlock CPA攻击 - 目标字节: %d\n", target_byte);
    printf("分析 %d 条功耗轨迹...\n", num_traces);
    
    result->max_overall_correlation = 0.0;
    result->best_key = 0;
    result->best_overall_time_point = 0;
    
    // 1. 完整字节攻击：枚举所有256个可能的密钥字节
    printf("\n=== 完整字节CPA攻击 ===\n");
    for (int key_guess = 0; key_guess < 256; key_guess++) {
        
        // 计算该密钥猜测的假设功耗值（基于完整S盒输出）
        double *hypothetical_power = malloc(num_traces * sizeof(double));
        
        for (int i = 0; i < num_traces; i++) {
            unsigned char sbox_output = compute_ublock_first_sbox_output(
                traces[i].plaintext.data[target_byte], 
                key_guess
            );
            hypothetical_power[i] = (double)hamming_weight(sbox_output);
        }
        
        // 对每个时间点计算相关系数
        result->max_correlation[key_guess] = 0.0;
        result->best_time_point[key_guess] = 0;
        
        for (int t = 0; t < TIME_POINTS; t++) {
            // 提取该时间点的实际功耗
            double *measured_power = malloc(num_traces * sizeof(double));
            
            for (int i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            // 计算相关系数
            double correlation = fabs(calculate_correlation(hypothetical_power, measured_power, num_traces));
            result->correlation[key_guess][t] = correlation;
            
            // 记录该密钥猜测的最大相关系数
            if (correlation > result->max_correlation[key_guess]) {
                result->max_correlation[key_guess] = correlation;
                result->best_time_point[key_guess] = t;
            }
            
            // 记录全局最大相关系数
            if (correlation > result->max_overall_correlation) {
                result->max_overall_correlation = correlation;
                result->best_key = key_guess;
                result->best_overall_time_point = t;
            }
            
            free(measured_power);
        }
        
        if (key_guess % 32 == 0) {
            printf("密钥猜测 0x%02X: 最大相关系数 = %.6f (时间点 %d)\n", 
                   key_guess, result->max_correlation[key_guess], result->best_time_point[key_guess]);
        }
        
        free(hypothetical_power);
    }
    
    // 2. Nibble级别攻击：分别攻击高4位和低4位
    printf("\n=== Nibble级别CPA攻击 ===\n");
    
    // 攻击高4位 (16个可能值)
    printf("攻击高4位nibble...\n");
    for (int nibble_guess = 0; nibble_guess < 16; nibble_guess++) {
        double *hypothetical_power_high = malloc(num_traces * sizeof(double));
        
        for (int i = 0; i < num_traces; i++) {
            unsigned char sbox_output_high = compute_ublock_high_nibble_sbox(
                traces[i].plaintext.data[target_byte], 
                nibble_guess << 4  // 只考虑高4位
            );
            hypothetical_power_high[i] = (double)hamming_weight_nibble(sbox_output_high);
        }
        
        double max_corr_high = 0.0;
        for (int t = 0; t < TIME_POINTS; t++) {
            double *measured_power = malloc(num_traces * sizeof(double));
            for (int i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            double correlation = fabs(calculate_correlation(hypothetical_power_high, measured_power, num_traces));
            result->nibble_correlation[nibble_guess][0][t] = correlation;
            
            if (correlation > max_corr_high) {
                max_corr_high = correlation;
            }
            
            free(measured_power);
        }
        
        result->high_nibble_correlation[nibble_guess] = max_corr_high;
        free(hypothetical_power_high);
    }
    
    // 攻击低4位 (16个可能值)
    printf("攻击低4位nibble...\n");
    for (int nibble_guess = 0; nibble_guess < 16; nibble_guess++) {
        double *hypothetical_power_low = malloc(num_traces * sizeof(double));
        
        for (int i = 0; i < num_traces; i++) {
            unsigned char sbox_output_low = compute_ublock_low_nibble_sbox(
                traces[i].plaintext.data[target_byte], 
                nibble_guess  // 只考虑低4位
            );
            hypothetical_power_low[i] = (double)hamming_weight_nibble(sbox_output_low);
        }
        
        double max_corr_low = 0.0;
        for (int t = 0; t < TIME_POINTS; t++) {
            double *measured_power = malloc(num_traces * sizeof(double));
            for (int i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            double correlation = fabs(calculate_correlation(hypothetical_power_low, measured_power, num_traces));
            result->nibble_correlation[nibble_guess][1][t] = correlation;
            
            if (correlation > max_corr_low) {
                max_corr_low = correlation;
            }
            
            free(measured_power);
        }
        
        result->low_nibble_correlation[nibble_guess] = max_corr_low;
        free(hypothetical_power_low);
    }
}

// 保存UBlock CPA攻击结果和生成可视化
void save_ublock_cpa_results(UBlock_PowerTrace *traces, UBlock_CPAResult *result, int num_traces, 
                             unsigned char correct_key, int target_byte) {
    printf("\n=== 保存UBlock CPA攻击结果 ===\n");
    
    // 1. 保存功耗轨迹样本
    FILE *fp = fopen("ublock_cpa_traces.dat", "w");
    if (fp) {
        fprintf(fp, "# Time_Point");
        for (int i = 0; i < 8 && i < num_traces; i++) {
            fprintf(fp, " Trace_%d", i);
        }
        fprintf(fp, "\n");
        
        for (int t = 0; t < TIME_POINTS; t++) {
            fprintf(fp, "%d", t);
            for (int i = 0; i < 8 && i < num_traces; i++) {
                fprintf(fp, " %.6f", traces[i].trace[t]);
            }
            fprintf(fp, "\n");
        }
        fclose(fp);
        printf("功耗轨迹保存到: ublock_cpa_traces.dat\n");
    }
    
    // 2. 保存完整字节攻击结果
    fp = fopen("ublock_cpa_byte_attack.dat", "w");
    if (fp) {
        fprintf(fp, "# Key_Guess Max_Correlation Best_Time_Point Is_Correct\n");
        for (int k = 0; k < 256; k++) {
            int is_correct = (k == correct_key) ? 1 : 0;
            fprintf(fp, "%d %.8f %d %d\n", k, result->max_correlation[k], result->best_time_point[k], is_correct);
        }
        fclose(fp);
        printf("字节级攻击结果保存到: ublock_cpa_byte_attack.dat\n");
    }
    
    // 3. 保存nibble攻击结果
    fp = fopen("ublock_cpa_nibble_attack.dat", "w");
    if (fp) {
        unsigned char correct_high = (correct_key >> 4) & 0xF;
        unsigned char correct_low = correct_key & 0xF;
        
        fprintf(fp, "# Nibble_Guess High_Nibble_Correlation Low_Nibble_Correlation Is_Correct_High Is_Correct_Low\n");
        for (int n = 0; n < 16; n++) {
            int is_correct_high = (n == correct_high) ? 1 : 0;
            int is_correct_low = (n == correct_low) ? 1 : 0;
            fprintf(fp, "%d %.8f %.8f %d %d\n", n, 
                    result->high_nibble_correlation[n], 
                    result->low_nibble_correlation[n],
                    is_correct_high, is_correct_low);
        }
        fclose(fp);
        printf("Nibble级攻击结果保存到: ublock_cpa_nibble_attack.dat\n");
    }
    
    // 4. 保存UBlock S盒输入输出关系验证
    fp = fopen("ublock_sbox_verification.dat", "w");
    if (fp) {
        fprintf(fp, "# SBOX_Input SBOX_Output Hamming_Weight Count\n");
        int sbox_count[16] = {0};
        double sbox_power_sum[16] = {0};
        
        for (int i = 0; i < 500 && i < num_traces; i++) {
            unsigned char sbox_out = compute_ublock_first_sbox_output(
                traces[i].plaintext.data[target_byte], correct_key);
            int hw = hamming_weight(sbox_out);
            
            double avg_power = 0.0;
            for (int t = SBOX_WINDOW_START; t <= SBOX_WINDOW_END; t++) {
                avg_power += traces[i].trace[t];
            }
            avg_power /= (SBOX_WINDOW_END - SBOX_WINDOW_START + 1);
            
            if (hw < 16) {
                sbox_power_sum[hw] += avg_power;
                sbox_count[hw]++;
            }
        }
        
        for (int hw = 0; hw < 9; hw++) {
            if (sbox_count[hw] > 0) {
                fprintf(fp, "%d %d %.6f %d\n", hw, hw, sbox_power_sum[hw] / sbox_count[hw], sbox_count[hw]);
            }
        }
        fclose(fp);
        printf("UBlock S盒验证数据保存到: ublock_sbox_verification.dat\n");
    }
    
    // 5. 生成UBlock专用可视化脚本 (修复版本)
    fp = fopen("plot_ublock_cpa.gnuplot", "w");
    if (fp) {
        fprintf(fp, "# UBlock CPA Attack Results Visualization Script (Fixed Version)\n");
        fprintf(fp, "# Fixes black overlay issues\n\n");
        
        // 使用简化的终端设置避免渲染问题
        fprintf(fp, "set terminal pngcairo size 1200,800 font \"Arial,10\"\n\n");
        
        // 图1: UBlock功耗轨迹
        fprintf(fp, "# Plot 1: UBlock Power Traces\n");
        fprintf(fp, "set output 'ublock_power_traces.png'\n");
        fprintf(fp, "set title 'UBlock CPA Attack - Power Traces'\n");
        fprintf(fp, "set xlabel 'Time Points'\n");
        fprintf(fp, "set ylabel 'Power Consumption'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set key top right\n");
        
        // 用箭头标记S盒窗口，避免矩形填充问题
        fprintf(fp, "set arrow from %d,graph 0 to %d,graph 1 nohead lc rgb 'red' lw 2\n", SBOX_WINDOW_START, SBOX_WINDOW_START);
        fprintf(fp, "set arrow from %d,graph 0 to %d,graph 1 nohead lc rgb 'red' lw 2\n", SBOX_WINDOW_END, SBOX_WINDOW_END);
        fprintf(fp, "set label \"S-box Window\" at %d,graph 0.9 center tc rgb 'red'\n", (SBOX_WINDOW_START + SBOX_WINDOW_END) / 2);
        
        fprintf(fp, "plot ");
        for (int i = 0; i < 6; i++) {
            fprintf(fp, "'ublock_cpa_traces.dat' using 1:%d with lines title 'Trace %d' lw 1", i+2, i);
            if (i < 5) fprintf(fp, ", \\\n     ");
        }
        fprintf(fp, "\n");
        fprintf(fp, "unset arrow\n");
        fprintf(fp, "unset label\n\n");
        
        // 图2: UBlock字节级攻击结果
        fprintf(fp, "# Plot 2: UBlock Byte-level Attack Results\n");
        fprintf(fp, "set output 'ublock_byte_attack.png'\n");
        fprintf(fp, "set title 'UBlock CPA Attack - Byte-level Results'\n");
        fprintf(fp, "set xlabel 'Key Guess'\n");
        fprintf(fp, "set ylabel 'Max Correlation'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set boxwidth 0.8 relative\n");
        fprintf(fp, "set style fill solid 0.5\n");
        fprintf(fp, "plot 'ublock_cpa_byte_attack.dat' using ($4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct Key (0x%02X)', \\\n", correct_key);
        fprintf(fp, "     'ublock_cpa_byte_attack.dat' using ($4==0?$1:1/0):2 with boxes lc rgb '#87CEEB' title 'Wrong Keys'\n\n");
        
        // 图3: UBlock高4位nibble攻击结果 (单独图)
        fprintf(fp, "# Plot 3: UBlock High Nibble Attack\n");
        fprintf(fp, "set output 'ublock_high_nibble.png'\n");
        fprintf(fp, "set title 'UBlock CPA Attack - High Nibble (Bits 7-4)'\n");
        fprintf(fp, "set xlabel 'High Nibble Guess'\n");
        fprintf(fp, "set ylabel 'Max Correlation'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set xrange [-0.5:15.5]\n");
        fprintf(fp, "set boxwidth 0.6\n");
        fprintf(fp, "plot 'ublock_cpa_nibble_attack.dat' using ($4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct High Nibble', \\\n");
        fprintf(fp, "     'ublock_cpa_nibble_attack.dat' using ($4==0?$1:1/0):2 with boxes lc rgb '#90EE90' title 'Wrong High Nibbles'\n\n");
        
        // 图4: UBlock低4位nibble攻击结果 (单独图)
        fprintf(fp, "# Plot 4: UBlock Low Nibble Attack\n");
        fprintf(fp, "set output 'ublock_low_nibble.png'\n");
        fprintf(fp, "set title 'UBlock CPA Attack - Low Nibble (Bits 3-0)'\n");
        fprintf(fp, "set xlabel 'Low Nibble Guess'\n");
        fprintf(fp, "set ylabel 'Max Correlation'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set xrange [-0.5:15.5]\n");
        fprintf(fp, "set boxwidth 0.6\n");
        fprintf(fp, "plot 'ublock_cpa_nibble_attack.dat' using ($5==1?$1:1/0):3 with boxes lc rgb 'blue' title 'Correct Low Nibble', \\\n");
        fprintf(fp, "     'ublock_cpa_nibble_attack.dat' using ($5==0?$1:1/0):3 with boxes lc rgb '#FFA500' title 'Wrong Low Nibbles'\n\n");
        
        // 图5: UBlock S盒验证
        fprintf(fp, "# Plot 5: UBlock S-box Verification\n");
        fprintf(fp, "set output 'ublock_sbox_verification.png'\n");
        fprintf(fp, "set title 'UBlock S-box Power Leakage Verification'\n");
        fprintf(fp, "set xlabel 'Hamming Weight of S-box Output'\n");
        fprintf(fp, "set ylabel 'Average Power'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set xrange [-0.5:8.5]\n");
        fprintf(fp, "plot 'ublock_sbox_verification.dat' using 1:3 with points pt 7 ps 1.5 lc rgb 'blue' title 'UBlock S-box Data', \\\n");
        fprintf(fp, "     'ublock_sbox_verification.dat' using 1:3 smooth csplines with lines lw 2 lc rgb 'red' title 'Trend Line'\n\n");
        
        // 图6: 攻击成功对比 (前32个密钥)
        fprintf(fp, "# Plot 6: Attack Success Comparison (First 32 Keys)\n");
        fprintf(fp, "set output 'ublock_attack_comparison.png'\n");
        fprintf(fp, "set title 'UBlock CPA Attack - First 32 Key Guesses'\n");
        fprintf(fp, "set xlabel 'Key Guess'\n");
        fprintf(fp, "set ylabel 'Max Correlation'\n");
        fprintf(fp, "set grid\n");
        fprintf(fp, "set xrange [-0.5:31.5]\n");
        fprintf(fp, "set boxwidth 0.8\n");
        fprintf(fp, "plot 'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct Key', \\\n");
        fprintf(fp, "     'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==0?$1:1/0):2 with boxes lc rgb 'cyan' title 'Wrong Keys'\n\n");
        
        fprintf(fp, "print 'UBlock CPA visualization completed successfully!'\n");
        fprintf(fp, "print 'Generated files:'\n");
        fprintf(fp, "print '  - ublock_power_traces.png'\n");
        fprintf(fp, "print '  - ublock_byte_attack.png'\n");
        fprintf(fp, "print '  - ublock_high_nibble.png'\n");
        fprintf(fp, "print '  - ublock_low_nibble.png'\n");
        fprintf(fp, "print '  - ublock_sbox_verification.png'\n");
        fprintf(fp, "print '  - ublock_attack_comparison.png'\n");
        
        fclose(fp);
        printf("UBlock可视化脚本保存到: plot_ublock_cpa.gnuplot\n");
    }
    
    // 尝试自动运行Gnuplot
    printf("\n=== 生成UBlock CPA可视化 ===\n");
    int gnuplot_result = system("gnuplot plot_ublock_cpa.gnuplot 2>/dev/null");
    
    if (gnuplot_result == 0) {
        printf("✅ UBlock CPA可视化生成成功!\n");
        printf("生成的UBlock专用图片:\n");
        printf("  📊 ublock_power_traces.png - UBlock功耗轨迹\n");
        printf("  📈 ublock_byte_attack.png - 字节级攻击结果\n");
        printf("  📉 ublock_nibble_attack.png - Nibble级攻击结果\n");
        printf("  🔍 ublock_sbox_verification.png - S盒泄漏验证\n");
    } else {
        printf("⚠️ Gnuplot未找到，请手动运行: gnuplot plot_ublock_cpa.gnuplot\n");
    }
}

// 打印十六进制数据
void print_hex(const char *label, unsigned char *data, int len) {
    printf("%-20s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf("\n%-22s", "");
    }
    printf("\n");
}

// 主函数
int main() {
    printf("================================================================\n");
    printf("                  UBlock专用CPA攻击分析程序\n");
    printf("        Correlation Power Analysis for UBlock Cipher\n");
    printf("================================================================\n\n");
    
    // 初始化随机数生成器
    srand((unsigned int)time(NULL));
    
    // 生成随机主密钥
    unsigned char master_key[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) {
        master_key[i] = rand() & 0xFF;
    }
    
    print_hex("UBlock主密钥", master_key, KEY_SIZE);
    
    // 初始化UBlock密钥调度
    printf("\n=== UBlock密钥调度 ===\n");
    ublock_key_schedule(master_key);
    
    printf("轮0子密钥(nibbles): ");
    for (int i = 0; i < 32; i++) {
        printf("%X ", UBlock_Subkey[0][i]);
        if ((i + 1) % 16 == 0) printf("\n%-21s", "");
    }
    printf("\n");
    
    // 攻击配置
    int target_byte = 0;
    printf("\n=== UBlock CPA攻击配置 ===\n");
    printf("目标字节位置: %d\n", target_byte);
    printf("目标字节值: 0x%02X\n", master_key[target_byte]);
    printf("高4位nibble: 0x%X\n", (master_key[target_byte] >> 4) & 0xF);
    printf("低4位nibble: 0x%X\n", master_key[target_byte] & 0xF);
    printf("功耗轨迹数量: %d\n", NUM_TRACES);
    printf("时间采样点数: %d\n", TIME_POINTS);
    printf("UBlock S盒操作窗口: %d - %d\n", SBOX_WINDOW_START, SBOX_WINDOW_END);
    printf("UBlock S盒大小: 4位输入 -> 4位输出\n");
    printf("功耗模型: P = %.1f × HW + %.1f + 噪声\n\n", AFFINE_A, AFFINE_B);
    
    // 生成UBlock功耗轨迹
    printf("=== 生成UBlock功耗轨迹 ===\n");
    UBlock_PowerTrace *traces = malloc(NUM_TRACES * sizeof(UBlock_PowerTrace));
    
    clock_t start_time = clock();
    
    for (int i = 0; i < NUM_TRACES; i++) {
        generate_ublock_power_trace(&traces[i], master_key, target_byte);
        
        if ((i + 1) % 1000 == 0) {
            printf("已生成 %d 条UBlock轨迹\n", i + 1);
        }
    }
    
    clock_t end_time = clock();
    double generation_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("UBlock功耗轨迹生成完成! 用时: %.2f 秒\n\n", generation_time);
    
    // 执行UBlock CPA攻击
    printf("=== 执行UBlock CPA攻击 ===\n");
    UBlock_CPAResult cpa_result = {0};
    
    start_time = clock();
    perform_ublock_cpa_attack(traces, NUM_TRACES, target_byte, &cpa_result);
    end_time = clock();
    
    double attack_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    // 显示UBlock攻击结果
    printf("\n=== UBlock CPA攻击结果 ===\n");
    printf("字节级攻击:\n");
    printf("  最佳密钥猜测: 0x%02X\n", cpa_result.best_key);
    printf("  正确密钥: 0x%02X\n", master_key[target_byte]);
    printf("  攻击是否成功: %s\n", (cpa_result.best_key == master_key[target_byte]) ? "✅ 成功" : "❌ 失败");
    printf("  最大相关系数: %.8f\n", cpa_result.max_overall_correlation);
    printf("  最佳时间点: %d\n", cpa_result.best_overall_time_point);
    
    // 分析nibble级攻击结果
    int best_high_nibble = 0, best_low_nibble = 0;
    double max_high_corr = 0.0, max_low_corr = 0.0;
    
    for (int i = 0; i < 16; i++) {
        if (cpa_result.high_nibble_correlation[i] > max_high_corr) {
            max_high_corr = cpa_result.high_nibble_correlation[i];
            best_high_nibble = i;
        }
        if (cpa_result.low_nibble_correlation[i] > max_low_corr) {
            max_low_corr = cpa_result.low_nibble_correlation[i];
            best_low_nibble = i;
        }
    }
    
    printf("\nNibble级攻击:\n");
    printf("  高4位最佳猜测: 0x%X (正确: 0x%X) %s\n", 
           best_high_nibble, (master_key[target_byte] >> 4) & 0xF,
           (best_high_nibble == ((master_key[target_byte] >> 4) & 0xF)) ? "✅" : "❌");
    printf("  高4位最大相关系数: %.8f\n", max_high_corr);
    printf("  低4位最佳猜测: 0x%X (正确: 0x%X) %s\n", 
           best_low_nibble, master_key[target_byte] & 0xF,
           (best_low_nibble == (master_key[target_byte] & 0xF)) ? "✅" : "❌");
    printf("  低4位最大相关系数: %.8f\n", max_low_corr);
    printf("  重构密钥: 0x%02X\n", (best_high_nibble << 4) | best_low_nibble);
    
    printf("UBlock攻击用时: %.2f 秒\n", attack_time);
    
    // 保存结果
    save_ublock_cpa_results(traces, &cpa_result, NUM_TRACES, master_key[target_byte], target_byte);
    
    // 释放内存
    free(traces);
    
    printf("\n================================================================\n");
    printf("                   UBlock CPA攻击分析完成\n");
    printf("================================================================\n");
    printf("总处理时间: %.2f 秒\n", generation_time + attack_time);
    printf("字节级攻击成功: %s\n", (cpa_result.best_key == master_key[target_byte]) ? "是" : "否");
    printf("Nibble级攻击成功: %s\n", 
           ((best_high_nibble == ((master_key[target_byte] >> 4) & 0xF)) && 
            (best_low_nibble == (master_key[target_byte] & 0xF))) ? "是" : "否");
    printf("\nUBlock特有特性:\n");
    printf("- 4位S盒设计允许独立攻击高低nibble\n");
    printf("- Nibble级攻击可能比字节级攻击更有效\n");
    printf("- UBlock的置换结构在第一轮不影响CPA攻击\n");
    printf("\n生成的UBlock专用文件:\n");
    printf("📁 ublock_cpa_*.dat - UBlock攻击数据\n");
    printf("📊 plot_ublock_cpa.gnuplot - UBlock可视化脚本\n");
    printf("🖼️ ublock_*.png - UBlock专用图表\n");
    printf("================================================================\n");
    
    return 0;
}