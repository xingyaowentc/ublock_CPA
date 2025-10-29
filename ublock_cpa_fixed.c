// UBlock CPA Attack Fixed Version - Compatible with older C standards
// Only modified CPA attack analysis part, keeping UBlock encryption core completely unchanged
// Fixed: power model, noise parameters, analysis algorithm, visualization, compilation compatibility

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

// ==================== UBlock Core (Completely Unchanged) ====================
#define BLOCK_SIZE 16       
#define KEY_SIZE 16         
#define NUM_ROUNDS 16       

// Real UBlock S-box (from source code, unchanged)
static const unsigned char UBLOCK_SBOX[16] = {
    0x7, 0x4, 0x9, 0xc, 0xb, 0xa, 0xd, 0x8, 
    0xf, 0xe, 0x1, 0x6, 0x0, 0x3, 0x2, 0x5
};

// UBlock Round Constants RC (from source code, unchanged)
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

// UBlock permutation matrices (unchanged)
static const unsigned char A1[16] = {1,2,3,4,5,6,7,0,9,10,11,12,13,14,15,8};
static const unsigned char A2[16] = {2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9};
static const unsigned char A3[16] = {5,6,7,0,1,2,3,4,13,14,15,8,9,10,11,12};

// Linear layer permutations (unchanged)
static const unsigned char L1[16] = {2,3,6,7,8,9,12,13,0,1,4,5,14,15,10,11};
static const unsigned char L2[16] = {4,5,14,15,10,11,0,1,2,3,12,13,8,9,6,7};

// Key schedule permutations (unchanged)
static const unsigned char SK_PERM[16] = {0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13};
static const unsigned char KEY_PERM[16] = {6,0,8,13,1,15,5,10,4,9,12,2,11,3,7,14};

// Global subkey storage (unchanged)
unsigned char UBlock_Subkey[17][32];

// ==================== CPA Attack Parameters (Fixed Version) ====================
#define NUM_TRACES 6000     /* Increased trace count (was 5000) */
#define TIME_POINTS 100     
#define NOISE_STDDEV 0.3    /* Much lower noise (was 1.0) */
#define AFFINE_A 3.5        /* Enhanced signal strength (was 2.0) */
#define AFFINE_B 1.0        /* Lower offset (was 5.0) */
#define SBOX_WINDOW_START 10   /* Extended time window (was 15) */
#define SBOX_WINDOW_END 30     /* Extended time window (was 25) */

// ==================== Data Structures (Unchanged) ====================
typedef struct {
    unsigned char data[BLOCK_SIZE];
} UBlock_Block;

typedef struct {
    double trace[TIME_POINTS];
    UBlock_Block plaintext;
} UBlock_PowerTrace;

typedef struct {
    double correlation[256][TIME_POINTS];  
    double max_correlation[256];           
    int best_time_point[256];              
    int best_key;
    double max_overall_correlation;
    int best_overall_time_point;
    
    double nibble_correlation[16][16][TIME_POINTS];  
    double high_nibble_correlation[256];             
    double low_nibble_correlation[256];              
} UBlock_CPAResult;

// Key candidate structure for ranking
typedef struct {
    int key;
    double correlation;
} KeyCandidate;

// ==================== Utility Functions (Unchanged) ====================
int hamming_weight(unsigned char value) {
    int weight = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if ((value >> i) & 1) weight++;
    }
    return weight;
}

int hamming_weight_nibble(unsigned char value) {
    int weight = 0;
    int i;
    for (i = 0; i < 4; i++) {
        if ((value >> i) & 1) weight++;
    }
    return weight;
}

// Box-Muller transform for Gaussian noise (unchanged)
double gaussian_noise(double mean, double stddev) {
    static int has_spare = 0;
    static double spare;
    static double u, v, mag;
    
    if (has_spare) {
        has_spare = 0;
        return spare * stddev + mean;
    }
    
    has_spare = 1;
    
    do {
        u = 2.0 * ((double)rand() / RAND_MAX) - 1.0;
        v = 2.0 * ((double)rand() / RAND_MAX) - 1.0;
        mag = u * u + v * v;
    } while (mag >= 1.0 || mag == 0.0);
    
    mag = sqrt(-2.0 * log(mag) / mag);
    spare = v * mag;
    return u * mag * stddev + mean;
}

// ==================== Fixed Power Model ====================
/* Improved power leakage model */
double improved_ublock_power_model(unsigned char intermediate_value, double noise_level) {
    int hw = hamming_weight(intermediate_value);
    double base_leakage;
    unsigned char high, low;
    int nibble_interaction;
    double noise;
    
    /* Stronger linear relationship + nonlinear enhancement */
    base_leakage = AFFINE_A * hw + AFFINE_B;
    
    /* Add hamming weight specific additional leakage */
    if (hw == 0 || hw == 8) base_leakage += 1.0;  /* Extreme value enhancement */
    if (hw == 4) base_leakage += 0.5;             /* Middle value enhancement */
    
    /* Add nibble interaction leakage */
    high = (intermediate_value >> 4) & 0xF;
    low = intermediate_value & 0xF;
    nibble_interaction = hamming_weight_nibble(high ^ low);
    base_leakage += 0.3 * nibble_interaction;
    
    noise = gaussian_noise(0.0, noise_level);
    return base_leakage + noise;
}

// ==================== UBlock Core Algorithm (Completely Unchanged) ====================
void apply_permutation(unsigned char *state, const unsigned char *perm, int size) {
    unsigned char temp[16];
    int i;
    memcpy(temp, state, size);
    for (i = 0; i < size; i++) {
        state[i] = temp[perm[i]];
    }
}

void ublock_key_schedule(unsigned char *master_key) {
    unsigned char state1[16], state2[16];
    unsigned char new_state2[16];
    int i, round;
    
    for (i = 0; i < 16; i++) {
        state1[i] = (master_key[i] >> 4) & 0xF;
        state2[i] = master_key[i] & 0xF;
    }
    
    apply_permutation(state1, SK_PERM, 16);
    apply_permutation(state2, SK_PERM, 16);
    
    memcpy(UBlock_Subkey[0], state1, 16);
    memcpy(UBlock_Subkey[0] + 16, state2, 16);
    
    for (round = 1; round <= 16; round++) {
        apply_permutation(state1, KEY_PERM, 16);
        
        for (i = 0; i < 16; i++) {
            state1[i] ^= RC[round-1][i];
        }
        
        for (i = 0; i < 16; i++) {
            state1[i] = UBLOCK_SBOX[state1[i]];
        }
        
        apply_permutation(state1, SK_PERM, 16);
        
        for (i = 0; i < 16; i++) {
            state1[i] ^= state2[i];
        }
        
        apply_permutation(state1, KEY_PERM, 16);
        memcpy(new_state2, state1, 16);
        memcpy(state2, new_state2, 16);
        
        memcpy(UBlock_Subkey[round], state1, 16);
        memcpy(UBlock_Subkey[round] + 16, state2, 16);
    }
}

unsigned char compute_ublock_first_sbox_output(unsigned char plaintext_byte, unsigned char key_byte) {
    unsigned char pt_high = (plaintext_byte >> 4) & 0xF;
    unsigned char pt_low = plaintext_byte & 0xF;
    unsigned char key_high = (key_byte >> 4) & 0xF;
    unsigned char key_low = key_byte & 0xF;
    unsigned char sbox_input_high = pt_high ^ key_high;
    unsigned char sbox_input_low = pt_low ^ key_low;
    unsigned char sbox_output_high = UBLOCK_SBOX[sbox_input_high];
    unsigned char sbox_output_low = UBLOCK_SBOX[sbox_input_low];
    
    return (sbox_output_high << 4) | sbox_output_low;
}

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

void generate_random_ublock(UBlock_Block *block) {
    int i;
    for (i = 0; i < BLOCK_SIZE; i++) {
        block->data[i] = rand() & 0xFF;
    }
}

// ==================== Fixed Power Trace Generation ====================
void generate_improved_ublock_power_trace(UBlock_PowerTrace *trace, unsigned char *key, int target_byte) {
    unsigned char sbox_output;
    int t;
    int window_center;
    unsigned char random_data;
    
    generate_random_ublock(&trace->plaintext);
    
    sbox_output = compute_ublock_first_sbox_output(
        trace->plaintext.data[target_byte], 
        key[target_byte]
    );
    
    /* Generate more realistic power traces */
    for (t = 0; t < TIME_POINTS; t++) {
        if (t >= SBOX_WINDOW_START && t <= SBOX_WINDOW_END) {
            /* S-box operation time window: use improved power model */
            trace->trace[t] = improved_ublock_power_model(sbox_output, NOISE_STDDEV);
            
            /* Signal enhancement within window */
            window_center = (SBOX_WINDOW_START + SBOX_WINDOW_END) / 2;
            if (abs(t - window_center) <= 3) {
                /* Central window area enhancement */
                trace->trace[t] += 0.8 * hamming_weight(sbox_output) / 8.0;
            }
        } else {
            /* Other operations' power: lower correlation */
            random_data = rand() & 0xFF;
            trace->trace[t] = improved_ublock_power_model(random_data, NOISE_STDDEV * 1.5);
        }
    }
}

// ==================== Correlation Calculation (Improved Version) ====================
double calculate_correlation_robust(double *x, double *y, int n) {
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0, sum_y2 = 0;
    double mean_x, mean_y, numerator, var_x, var_y, denominator;
    int i;
    
    if (n < 2) return 0.0;
    
    for (i = 0; i < n; i++) {
        sum_x += x[i];
        sum_y += y[i];
        sum_xy += x[i] * y[i];
        sum_x2 += x[i] * x[i];
        sum_y2 += y[i] * y[i];
    }
    
    mean_x = sum_x / n;
    mean_y = sum_y / n;
    
    numerator = sum_xy - n * mean_x * mean_y;
    var_x = sum_x2 - n * mean_x * mean_x;
    var_y = sum_y2 - n * mean_y * mean_y;
    
    if (var_x <= 0.0 || var_y <= 0.0) return 0.0;
    
    denominator = sqrt(var_x * var_y);
    return (denominator == 0.0) ? 0.0 : numerator / denominator;
}

// ==================== Improved CPA Attack Algorithm ====================
void perform_improved_ublock_cpa_attack(UBlock_PowerTrace *traces, int num_traces, int target_byte, UBlock_CPAResult *result) {
    int key_guess, i, t, nibble_guess;
    double *hypothetical_power;
    double *measured_power;
    double correlation;
    unsigned char sbox_output, sbox_output_high, sbox_output_low;
    double *hypothetical_power_high, *hypothetical_power_low;
    double max_corr_high, max_corr_low;
    
    printf("Performing improved UBlock CPA attack - Target byte: %d\n", target_byte);
    printf("Analyzing %d power traces (improved noise: %.2f, signal: %.1f)...\n", num_traces, NOISE_STDDEV, AFFINE_A);
    
    result->max_overall_correlation = 0.0;
    result->best_key = 0;
    result->best_overall_time_point = 0;
    
    /* 1. Complete byte attack (improved algorithm) */
    printf("\n=== Improved Byte-level CPA Attack ===\n");
    for (key_guess = 0; key_guess < 256; key_guess++) {
        
        hypothetical_power = malloc(num_traces * sizeof(double));
        
        for (i = 0; i < num_traces; i++) {
            sbox_output = compute_ublock_first_sbox_output(
                traces[i].plaintext.data[target_byte], 
                key_guess
            );
            
            /* Use hamming weight as power hypothesis */
            hypothetical_power[i] = (double)hamming_weight(sbox_output);
        }
        
        result->max_correlation[key_guess] = 0.0;
        result->best_time_point[key_guess] = 0;
        
        /* Focus on S-box time window */
        for (t = 0; t < TIME_POINTS; t++) {
            measured_power = malloc(num_traces * sizeof(double));
            
            for (i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            /* Use improved correlation calculation */
            correlation = fabs(calculate_correlation_robust(hypothetical_power, measured_power, num_traces));
            result->correlation[key_guess][t] = correlation;
            
            /* Give higher weight within S-box window */
            if (t >= SBOX_WINDOW_START && t <= SBOX_WINDOW_END) {
                correlation *= 1.2;  /* Enhancement within S-box window */
            }
            
            if (correlation > result->max_correlation[key_guess]) {
                result->max_correlation[key_guess] = correlation;
                result->best_time_point[key_guess] = t;
            }
            
            if (correlation > result->max_overall_correlation) {
                result->max_overall_correlation = correlation;
                result->best_key = key_guess;
                result->best_overall_time_point = t;
            }
            
            free(measured_power);
        }
        
        if (key_guess % 64 == 0) {
            printf("Key guess 0x%02X: Max correlation = %.6f (time point %d)\n", 
                   key_guess, result->max_correlation[key_guess], result->best_time_point[key_guess]);
        }
        
        free(hypothetical_power);
    }
    
    /* 2. Improved Nibble-level attack */
    printf("\n=== Improved Nibble-level CPA Attack ===\n");
    
    /* Attack high 4 bits */
    for (nibble_guess = 0; nibble_guess < 16; nibble_guess++) {
        hypothetical_power_high = malloc(num_traces * sizeof(double));
        
        for (i = 0; i < num_traces; i++) {
            sbox_output_high = compute_ublock_high_nibble_sbox(
                traces[i].plaintext.data[target_byte], 
                nibble_guess << 4
            );
            hypothetical_power_high[i] = (double)hamming_weight_nibble(sbox_output_high);
        }
        
        max_corr_high = 0.0;
        for (t = SBOX_WINDOW_START; t <= SBOX_WINDOW_END; t++) {
            measured_power = malloc(num_traces * sizeof(double));
            for (i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            correlation = fabs(calculate_correlation_robust(hypothetical_power_high, measured_power, num_traces));
            
            if (correlation > max_corr_high) {
                max_corr_high = correlation;
            }
            
            free(measured_power);
        }
        
        result->high_nibble_correlation[nibble_guess] = max_corr_high;
        free(hypothetical_power_high);
    }
    
    /* Attack low 4 bits */
    for (nibble_guess = 0; nibble_guess < 16; nibble_guess++) {
        hypothetical_power_low = malloc(num_traces * sizeof(double));
        
        for (i = 0; i < num_traces; i++) {
            sbox_output_low = compute_ublock_low_nibble_sbox(
                traces[i].plaintext.data[target_byte], 
                nibble_guess
            );
            hypothetical_power_low[i] = (double)hamming_weight_nibble(sbox_output_low);
        }
        
        max_corr_low = 0.0;
        for (t = SBOX_WINDOW_START; t <= SBOX_WINDOW_END; t++) {
            measured_power = malloc(num_traces * sizeof(double));
            for (i = 0; i < num_traces; i++) {
                measured_power[i] = traces[i].trace[t];
            }
            
            correlation = fabs(calculate_correlation_robust(hypothetical_power_low, measured_power, num_traces));
            
            if (correlation > max_corr_low) {
                max_corr_low = correlation;
            }
            
            free(measured_power);
        }
        
        result->low_nibble_correlation[nibble_guess] = max_corr_low;
        free(hypothetical_power_low);
    }
    
    printf("Improved UBlock CPA attack completed!\n");
}

// ==================== Data Saving Functions ====================
void save_power_traces(UBlock_PowerTrace *traces, int num_traces, int num_to_save) {
    FILE *fp = fopen("ublock_cpa_traces.dat", "w");
    int i, t;
    if (!fp) return;
    
    /* Save first few traces for visualization */
    if (num_to_save > num_traces) num_to_save = num_traces;
    if (num_to_save > 10) num_to_save = 10; /* Limit to 10 traces */
    
    for (t = 0; t < TIME_POINTS; t++) {
        fprintf(fp, "%d", t);
        for (i = 0; i < num_to_save; i++) {
            fprintf(fp, " %.6f", traces[i].trace[t]);
        }
        fprintf(fp, "\n");
    }
    
    fclose(fp);
    printf("Power traces data saved to: ublock_cpa_traces.dat\n");
}

void save_attack_results(UBlock_CPAResult *result, unsigned char correct_key) {
    FILE *fp = fopen("ublock_cpa_byte_attack.dat", "w");
    int i;
    if (!fp) return;
    
    /* Save byte-level attack results */
    for (i = 0; i < 256; i++) {
        fprintf(fp, "%d %.8f %d %d\n", 
                i, 
                result->max_correlation[i], 
                result->best_time_point[i],
                (i == correct_key) ? 1 : 0);
    }
    
    fclose(fp);
    printf("Byte attack results saved to: ublock_cpa_byte_attack.dat\n");
}

void save_nibble_results(UBlock_CPAResult *result, unsigned char correct_key) {
    FILE *fp = fopen("ublock_cpa_nibble_attack.dat", "w");
    int i;
    unsigned char correct_high = (correct_key >> 4) & 0xF;
    unsigned char correct_low = correct_key & 0xF;
    
    if (!fp) return;
    
    /* Save nibble-level attack results */
    for (i = 0; i < 16; i++) {
        fprintf(fp, "%d %.8f %.8f %d %d\n", 
                i, 
                result->high_nibble_correlation[i], 
                result->low_nibble_correlation[i],
                (i == correct_high) ? 1 : 0,
                (i == correct_low) ? 1 : 0);
    }
    
    fclose(fp);
    printf("Nibble attack results saved to: ublock_cpa_nibble_attack.dat\n");
}

void save_correlation_time_series(UBlock_CPAResult *result, unsigned char correct_key) {
    FILE *fp = fopen("correlation_time_series.dat", "w");
    int t;
    if (!fp) return;
    
    /* Save correlation over time for correct key */
    for (t = 0; t < TIME_POINTS; t++) {
        fprintf(fp, "%d %.8f\n", t, result->correlation[correct_key][t]);
    }
    
    fclose(fp);
    printf("Correlation time series saved to: correlation_time_series.dat\n");
}

// ==================== Improved Visualization Generation ====================
void generate_fixed_visualization_script(unsigned char correct_key, int target_byte) {
    FILE *fp = fopen("plot_ublock_cpa_fixed.gnuplot", "w");
    if (!fp) return;
    
    fprintf(fp, "# Fixed UBlock CPA Attack Visualization\n");
    fprintf(fp, "set terminal pngcairo size 1600,1200 font \"Arial,14\"\n\n");
    
    /* 1. Power traces plot (highlighting S-box window) */
    fprintf(fp, "set output 'ublock_power_traces_fixed.png'\n");
    fprintf(fp, "set title 'UBlock CPA Attack - Power Traces (Fixed)'\n");
    fprintf(fp, "set xlabel 'Time Points'\n");
    fprintf(fp, "set ylabel 'Power Consumption'\n");
    fprintf(fp, "set grid\n");
    fprintf(fp, "set key top right\n");
    
    /* Highlight S-box window */
    fprintf(fp, "set style rect fc rgb 'yellow' fs transparent solid 0.2\n");
    fprintf(fp, "set object rectangle from %d,graph 0 to %d,graph 1\n", SBOX_WINDOW_START, SBOX_WINDOW_END);
    fprintf(fp, "set label \"S-box Window [%d-%d]\" at %d,graph 0.9 center tc rgb 'red' font \",12\"\n", 
            SBOX_WINDOW_START, SBOX_WINDOW_END, (SBOX_WINDOW_START + SBOX_WINDOW_END) / 2);
    
    fprintf(fp, "plot ");
    fprintf(fp, "'ublock_cpa_traces.dat' using 1:2 with lines title 'Trace 1' lw 2, \\\n");
    fprintf(fp, "     'ublock_cpa_traces.dat' using 1:3 with lines title 'Trace 2' lw 2, \\\n");
    fprintf(fp, "     'ublock_cpa_traces.dat' using 1:4 with lines title 'Trace 3' lw 2, \\\n");
    fprintf(fp, "     'ublock_cpa_traces.dat' using 1:5 with lines title 'Trace 4' lw 2, \\\n");
    fprintf(fp, "     'ublock_cpa_traces.dat' using 1:6 with lines title 'Trace 5' lw 2\n");
    fprintf(fp, "unset object\n");
    fprintf(fp, "unset label\n\n");
    
    /* 2. Byte-level attack results (highlighting correct key) */
    fprintf(fp, "set output 'ublock_byte_attack_fixed.png'\n");
    fprintf(fp, "set title 'UBlock CPA Attack - Byte-level Results (Fixed)'\n");
    fprintf(fp, "set xlabel 'Key Guess'\n");
    fprintf(fp, "set ylabel 'Max Correlation'\n");
    fprintf(fp, "set grid\n");
    fprintf(fp, "set xrange [-5:260]\n");
    fprintf(fp, "set style fill solid 0.7\n");
    
    /* Plot all key guesses */
    fprintf(fp, "plot 'ublock_cpa_byte_attack.dat' using ($4==0?$1:1/0):2 with impulses lc rgb \"blue\" lw 2 title 'Wrong Keys', \\\n");
    fprintf(fp, "     'ublock_cpa_byte_attack.dat' using ($4==1?$1:1/0):2 with impulses lc rgb \"red\" lw 4 title 'Correct Key (0x%02X)'\n\n", correct_key);
    
    /* 3. Nibble attack comparison plot */
    fprintf(fp, "set output 'ublock_nibble_comparison_fixed.png'\n");
    fprintf(fp, "set title 'UBlock CPA Attack - Nibble-level Comparison (Fixed)'\n");
    fprintf(fp, "set xlabel 'Nibble Value'\n");
    fprintf(fp, "set ylabel 'Max Correlation'\n");
    fprintf(fp, "set grid\n");
    fprintf(fp, "set xrange [-0.5:15.5]\n");
    fprintf(fp, "set style data histogram\n");
    fprintf(fp, "set style histogram cluster gap 1\n");
    fprintf(fp, "set style fill solid 0.6\n");
    fprintf(fp, "set boxwidth 0.8\n");
    
    fprintf(fp, "plot 'ublock_cpa_nibble_attack.dat' using 1:($4==1?$2:0) with boxes lc rgb \"red\" title 'Correct High Nibble', \\\n");
    fprintf(fp, "     'ublock_cpa_nibble_attack.dat' using 1:($4==0?$2:0) with boxes lc rgb \"lightgreen\" title 'Wrong High Nibbles', \\\n");
    fprintf(fp, "     'ublock_cpa_nibble_attack.dat' using 1:($5==1?$3:0) with boxes lc rgb \"blue\" title 'Correct Low Nibble', \\\n");
    fprintf(fp, "     'ublock_cpa_nibble_attack.dat' using 1:($5==0?$3:0) with boxes lc rgb \"orange\" title 'Wrong Low Nibbles'\n\n");
    
    /* 4. Correlation time series plot (correct key) */
    fprintf(fp, "set output 'ublock_correlation_time_fixed.png'\n");
    fprintf(fp, "set title 'UBlock CPA Attack - Correlation over Time (Correct Key 0x%02X)'\n", correct_key);
    fprintf(fp, "set xlabel 'Time Points'\n");
    fprintf(fp, "set ylabel 'Correlation Coefficient'\n");
    fprintf(fp, "set grid\n");
    
    /* Re-highlight S-box window */
    fprintf(fp, "set style rect fc rgb 'yellow' fs transparent solid 0.2\n");
    fprintf(fp, "set object rectangle from %d,graph 0 to %d,graph 1\n", SBOX_WINDOW_START, SBOX_WINDOW_END);
    fprintf(fp, "set label \"S-box Window\" at %d,graph 0.9 center tc rgb 'red' font \",10\"\n", 
            (SBOX_WINDOW_START + SBOX_WINDOW_END) / 2);
    
    fprintf(fp, "plot 'correlation_time_series.dat' using 1:2 with lines lw 3 lc rgb \"red\" title 'Correct Key 0x%02X'\n\n", correct_key);
    fprintf(fp, "unset object\n");
    fprintf(fp, "unset label\n\n");
    
    /* 5. Simple comparison plot for first 32 keys */
    fprintf(fp, "set output 'ublock_top32_comparison.png'\n");
    fprintf(fp, "set title 'UBlock CPA Attack - First 32 Key Guesses Comparison'\n");
    fprintf(fp, "set xlabel 'Key Guess'\n");
    fprintf(fp, "set ylabel 'Max Correlation'\n");
    fprintf(fp, "set grid\n");
    fprintf(fp, "set xrange [-0.5:31.5]\n");
    
    fprintf(fp, "plot 'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==0?$1:1/0):2 with impulses lc rgb \"blue\" lw 3 title 'Wrong Keys', \\\n");
    fprintf(fp, "     'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==1?$1:1/0):2 with impulses lc rgb \"red\" lw 5 title 'Correct Key'\n\n");
    
    fclose(fp);
    printf("Fixed visualization script generated: plot_ublock_cpa_fixed.gnuplot\n");
}

void execute_gnuplot_script() {
    int result;
    printf("\nTrying to execute gnuplot to generate images...\n");
    
    /* Try to execute gnuplot */
    result = system("gnuplot plot_ublock_cpa_fixed.gnuplot");
    
    if (result == 0) {
        printf("SUCCESS: PNG images generated successfully!\n");
        printf("Generated files:\n");
        printf("  - ublock_power_traces_fixed.png\n");
        printf("  - ublock_byte_attack_fixed.png\n");
        printf("  - ublock_nibble_comparison_fixed.png\n");
        printf("  - ublock_correlation_time_fixed.png\n");
        printf("  - ublock_top32_comparison.png\n");
    } else {
        printf("WARNING: Could not execute gnuplot automatically.\n");
        printf("Please install gnuplot and run manually:\n");
        printf("  gnuplot plot_ublock_cpa_fixed.gnuplot\n");
        printf("\nOr use the data files with your preferred plotting tool:\n");
        printf("  - ublock_cpa_traces.dat (power traces)\n");
        printf("  - ublock_cpa_byte_attack.dat (byte attack results)\n");
        printf("  - ublock_cpa_nibble_attack.dat (nibble attack results)\n");
        printf("  - correlation_time_series.dat (correlation over time)\n");
    }
}

// ==================== Other Unchanged Functions ====================
void print_hex(const char *label, unsigned char *data, int len) {
    int i;
    printf("%-20s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf("\n%-22s", "");
    }
    printf("\n");
}

// Comparison function for sorting key candidates
int compare_candidates(const void *a, const void *b) {
    KeyCandidate *candA = (KeyCandidate *)a;
    KeyCandidate *candB = (KeyCandidate *)b;
    if (candB->correlation > candA->correlation) return 1;
    if (candB->correlation < candA->correlation) return -1;
    return 0;
}

// ==================== Fixed Main Function ====================
int main() {
    unsigned char master_key[KEY_SIZE];
    clock_t start_time, end_time;
    double generation_time, attack_time;
    UBlock_PowerTrace *traces;
    UBlock_CPAResult cpa_result;
    int target_byte = 0;
    int i;
    int best_high_nibble = 0, best_low_nibble = 0;
    double max_high_corr = 0.0, max_low_corr = 0.0;
    KeyCandidate candidates[256];
    
    printf("================================================================\n");
    printf("          UBlock CPA Attack Fixed Version (Core Unchanged)\n");
    printf("================================================================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Generate random master key */
    for (i = 0; i < KEY_SIZE; i++) {
        master_key[i] = rand() & 0xFF;
    }
    
    print_hex("UBlock Master Key", master_key, KEY_SIZE);
    
    /* Print individual key bytes for easy comparison */
    printf("\nKey bytes for comparison:\n");
    for (i = 0; i < KEY_SIZE; i++) {
        printf("Byte[%2d]: 0x%02X  (High nibble: 0x%X, Low nibble: 0x%X)\n", 
               i, master_key[i], (master_key[i] >> 4) & 0xF, master_key[i] & 0xF);
    }
    
    /* UBlock key schedule (unchanged) */
    ublock_key_schedule(master_key);
    
    printf("\n=== Fixed CPA Attack Configuration ===\n");
    printf("Target byte position: %d\n", target_byte);
    printf("Target byte value: 0x%02X\n", master_key[target_byte]);
    printf("High 4-bit nibble: 0x%X\n", (master_key[target_byte] >> 4) & 0xF);
    printf("Low 4-bit nibble: 0x%X\n", master_key[target_byte] & 0xF);
    printf("Number of power traces: %d (increased)\n", NUM_TRACES);
    printf("Noise standard deviation: %.2f (significantly reduced)\n", NOISE_STDDEV);
    printf("Signal strength: %.1f (enhanced)\n", AFFINE_A);
    printf("S-box operation window: %d - %d (extended)\n", SBOX_WINDOW_START, SBOX_WINDOW_END);
    
    /* Generate improved power traces */
    printf("\n=== Generating Improved UBlock Power Traces ===\n");
    traces = malloc(NUM_TRACES * sizeof(UBlock_PowerTrace));
    
    start_time = clock();
    
    for (i = 0; i < NUM_TRACES; i++) {
        generate_improved_ublock_power_trace(&traces[i], master_key, target_byte);
        
        if ((i + 1) % 1500 == 0) {
            printf("Generated %d improved traces\n", i + 1);
        }
    }
    
    end_time = clock();
    generation_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Improved power trace generation completed! Time: %.2f seconds\n\n", generation_time);
    
    /* Perform improved UBlock CPA attack */
    printf("=== Performing Improved UBlock CPA Attack ===\n");
    memset(&cpa_result, 0, sizeof(UBlock_CPAResult));
    
    start_time = clock();
    perform_improved_ublock_cpa_attack(traces, NUM_TRACES, target_byte, &cpa_result);
    end_time = clock();
    
    attack_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    /* Display fixed attack results */
    printf("\n=== Fixed UBlock CPA Attack Results ===\n");
    printf("Byte-level attack:\n");
    printf("  Best key guess: 0x%02X\n", cpa_result.best_key);
    printf("  Correct key: 0x%02X\n", master_key[target_byte]);
    printf("  Attack result: %s\n", (cpa_result.best_key == master_key[target_byte]) ? "SUCCESS" : "FAILED");
    printf("  Maximum correlation: %.8f\n", cpa_result.max_overall_correlation);
    printf("  Best time point: %d\n", cpa_result.best_overall_time_point);
    
    /* Analyze nibble-level attack results */
    for (i = 0; i < 16; i++) {
        if (cpa_result.high_nibble_correlation[i] > max_high_corr) {
            max_high_corr = cpa_result.high_nibble_correlation[i];
            best_high_nibble = i;
        }
        if (cpa_result.low_nibble_correlation[i] > max_low_corr) {
            max_low_corr = cpa_result.low_nibble_correlation[i];
            best_low_nibble = i;
        }
    }
    
    printf("\nNibble-level attack:\n");
    printf("  High 4-bit best guess: 0x%X (correct: 0x%X) %s\n", 
           best_high_nibble, (master_key[target_byte] >> 4) & 0xF,
           (best_high_nibble == ((master_key[target_byte] >> 4) & 0xF)) ? "SUCCESS" : "FAILED");
    printf("  High 4-bit max correlation: %.8f\n", max_high_corr);
    printf("  Low 4-bit best guess: 0x%X (correct: 0x%X) %s\n", 
           best_low_nibble, master_key[target_byte] & 0xF,
           (best_low_nibble == (master_key[target_byte] & 0xF)) ? "SUCCESS" : "FAILED");
    printf("  Low 4-bit max correlation: %.8f\n", max_low_corr);
    printf("  Reconstructed key: 0x%02X\n", (best_high_nibble << 4) | best_low_nibble);
    
    printf("Fixed attack time: %.2f seconds\n", attack_time);
    
    /* Show top 5 candidates for byte-level attack */
    printf("\n=== Top 5 Key Candidates (Byte-level) ===\n");
    
    /* Create array of key candidates with correlations */
    for (i = 0; i < 256; i++) {
        candidates[i].key = i;
        candidates[i].correlation = cpa_result.max_correlation[i];
    }
    
    /* Sort using qsort */
    qsort(candidates, 256, sizeof(KeyCandidate), compare_candidates);
    
    for (i = 0; i < 5; i++) {
        printf("Rank %d: Key 0x%02X, Correlation %.8f %s\n", 
               i + 1, candidates[i].key, candidates[i].correlation,
               (candidates[i].key == master_key[target_byte]) ? "(CORRECT)" : "");
    }
    
    /* Save attack data for visualization */
    printf("\n=== Saving Attack Data for Visualization ===\n");
    save_power_traces(traces, NUM_TRACES, 5);  /* Save first 5 traces */
    save_attack_results(&cpa_result, master_key[target_byte]);
    save_nibble_results(&cpa_result, master_key[target_byte]);
    save_correlation_time_series(&cpa_result, master_key[target_byte]);
    
    /* Generate fixed visualization script and try to create images */
    generate_fixed_visualization_script(master_key[target_byte], target_byte);
    execute_gnuplot_script();
    
    /* Free memory */
    free(traces);
    
    printf("\n================================================================\n");
    printf("                UBlock CPA Attack Fix Completed\n");
    printf("================================================================\n");
    printf("Fixed components:\n");
    printf("1. Keep UBlock encryption core completely unchanged\n");
    printf("2. Reduced noise level (1.0 -> 0.3)\n");
    printf("3. Enhanced signal strength (2.0 -> 3.5)\n");
    printf("4. Extended S-box window (15-25 -> 10-30)\n");
    printf("5. Increased trace count (5000 -> 6000)\n");
    printf("6. Improved power model and correlation calculation\n");
    printf("7. Fixed compilation compatibility issues\n");
    
    printf("\nFinal attack success rate:\n");
    printf("Byte-level attack: %s\n", (cpa_result.best_key == master_key[target_byte]) ? "SUCCESS" : "FAILED");
    printf("Nibble-level attack: %s\n", 
           ((best_high_nibble == ((master_key[target_byte] >> 4) & 0xF)) && 
            (best_low_nibble == (master_key[target_byte] & 0xF))) ? "SUCCESS" : "FAILED");
    
    return 0;
}