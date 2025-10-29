# UBlock CPA Attack Results Visualization Script (Fixed Version)
# Fixes black overlay issues

set terminal pngcairo size 1200,800 font "Arial,10"

# Plot 1: UBlock Power Traces
set output 'ublock_power_traces.png'
set title 'UBlock CPA Attack - Power Traces'
set xlabel 'Time Points'
set ylabel 'Power Consumption'
set grid
set key top right
set arrow from 15,graph 0 to 15,graph 1 nohead lc rgb 'red' lw 2
set arrow from 25,graph 0 to 25,graph 1 nohead lc rgb 'red' lw 2
set label "S-box Window" at 20,graph 0.9 center tc rgb 'red'
plot 'ublock_cpa_traces.dat' using 1:2 with lines title 'Trace 0' lw 1, \
     'ublock_cpa_traces.dat' using 1:3 with lines title 'Trace 1' lw 1, \
     'ublock_cpa_traces.dat' using 1:4 with lines title 'Trace 2' lw 1, \
     'ublock_cpa_traces.dat' using 1:5 with lines title 'Trace 3' lw 1, \
     'ublock_cpa_traces.dat' using 1:6 with lines title 'Trace 4' lw 1, \
     'ublock_cpa_traces.dat' using 1:7 with lines title 'Trace 5' lw 1
unset arrow
unset label

# Plot 2: UBlock Byte-level Attack Results
set output 'ublock_byte_attack.png'
set title 'UBlock CPA Attack - Byte-level Results'
set xlabel 'Key Guess'
set ylabel 'Max Correlation'
set grid
set boxwidth 0.8 relative
set style fill solid 0.5
plot 'ublock_cpa_byte_attack.dat' using ($4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct Key (0xD1)', \
     'ublock_cpa_byte_attack.dat' using ($4==0?$1:1/0):2 with boxes lc rgb '#87CEEB' title 'Wrong Keys'

# Plot 3: UBlock High Nibble Attack
set output 'ublock_high_nibble.png'
set title 'UBlock CPA Attack - High Nibble (Bits 7-4)'
set xlabel 'High Nibble Guess'
set ylabel 'Max Correlation'
set grid
set xrange [-0.5:15.5]
set boxwidth 0.6
plot 'ublock_cpa_nibble_attack.dat' using ($4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct High Nibble', \
     'ublock_cpa_nibble_attack.dat' using ($4==0?$1:1/0):2 with boxes lc rgb '#90EE90' title 'Wrong High Nibbles'

# Plot 4: UBlock Low Nibble Attack
set output 'ublock_low_nibble.png'
set title 'UBlock CPA Attack - Low Nibble (Bits 3-0)'
set xlabel 'Low Nibble Guess'
set ylabel 'Max Correlation'
set grid
set xrange [-0.5:15.5]
set boxwidth 0.6
plot 'ublock_cpa_nibble_attack.dat' using ($5==1?$1:1/0):3 with boxes lc rgb 'blue' title 'Correct Low Nibble', \
     'ublock_cpa_nibble_attack.dat' using ($5==0?$1:1/0):3 with boxes lc rgb '#FFA500' title 'Wrong Low Nibbles'

# Plot 5: UBlock S-box Verification
set output 'ublock_sbox_verification.png'
set title 'UBlock S-box Power Leakage Verification'
set xlabel 'Hamming Weight of S-box Output'
set ylabel 'Average Power'
set grid
set xrange [-0.5:8.5]
plot 'ublock_sbox_verification.dat' using 1:3 with points pt 7 ps 1.5 lc rgb 'blue' title 'UBlock S-box Data', \
     'ublock_sbox_verification.dat' using 1:3 smooth csplines with lines lw 2 lc rgb 'red' title 'Trend Line'

# Plot 6: Attack Success Comparison (First 32 Keys)
set output 'ublock_attack_comparison.png'
set title 'UBlock CPA Attack - First 32 Key Guesses'
set xlabel 'Key Guess'
set ylabel 'Max Correlation'
set grid
set xrange [-0.5:31.5]
set boxwidth 0.8
plot 'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==1?$1:1/0):2 with boxes lc rgb 'red' title 'Correct Key', \
     'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==0?$1:1/0):2 with boxes lc rgb 'cyan' title 'Wrong Keys'

print 'UBlock CPA visualization completed successfully!'
print 'Generated files:'
print '  - ublock_power_traces.png'
print '  - ublock_byte_attack.png'
print '  - ublock_high_nibble.png'
print '  - ublock_low_nibble.png'
print '  - ublock_sbox_verification.png'
print '  - ublock_attack_comparison.png'
