# Fixed UBlock CPA Attack Visualization
set terminal pngcairo size 1600,1200 font "Arial,14"

set output 'ublock_power_traces_fixed.png'
set title 'UBlock CPA Attack - Power Traces (Fixed)'
set xlabel 'Time Points'
set ylabel 'Power Consumption'
set grid
set key top right
set style rect fc rgb 'yellow' fs transparent solid 0.2
set object rectangle from 8,graph 0 to 35,graph 1
set label "S-box Window [8-35]" at 21,graph 0.9 center tc rgb 'red' font ",12"
plot 'ublock_cpa_traces.dat' using 1:2 with lines title 'Trace 0' lw 2, \
     'ublock_cpa_traces.dat' using 1:3 with lines title 'Trace 1' lw 2, \
     'ublock_cpa_traces.dat' using 1:4 with lines title 'Trace 2' lw 2, \
     'ublock_cpa_traces.dat' using 1:5 with lines title 'Trace 3' lw 2, \
     'ublock_cpa_traces.dat' using 1:6 with lines title 'Trace 4' lw 2, \
     'ublock_cpa_traces.dat' using 1:7 with lines title 'Trace 5' lw 2
unset object
unset label

set output 'ublock_byte_attack_fixed.png'
set title 'UBlock CPA Attack - Byte-level Results (Fixed)'
set xlabel 'Key Guess'
set ylabel 'Max Correlation'
set grid
set xrange [-5:260]
set style fill solid 0.7
plot 'ublock_cpa_byte_attack.dat' using ($4==0?$1:1/0):2 with impulses lc rgb "#87CEEB" lw 2 title 'Wrong Keys', \
     'ublock_cpa_byte_attack.dat' using ($4==1?$1:1/0):2 with impulses lc rgb "red" lw 4 title 'Correct Key (0xEA)'

set output 'ublock_nibble_comparison_fixed.png'
set title 'UBlock CPA Attack - Nibble-level Comparison (Fixed)'
set xlabel 'Nibble Value'
set ylabel 'Max Correlation'
set grid
set xrange [-0.5:15.5]
set style data histograms
set style histogram cluster gap 1
set style fill solid 0.6
set boxwidth 0.8
plot 'ublock_cpa_nibble_attack.dat' using 1:($4==1?$2:0) with boxes lc rgb "red" title 'Correct High Nibble', \
     'ublock_cpa_nibble_attack.dat' using 1:($4==0?$2:0) with boxes lc rgb "#90EE90" title 'Wrong High Nibbles', \
     'ublock_cpa_nibble_attack.dat' using 1:($5==1?$3:0) with boxes lc rgb "blue" title 'Correct Low Nibble', \
     'ublock_cpa_nibble_attack.dat' using 1:($5==0?$3:0) with boxes lc rgb "#FFA500" title 'Wrong Low Nibbles'

set output 'ublock_correlation_time_fixed.png'
set title 'UBlock CPA Attack - Correlation over Time (Correct Key)'
set xlabel 'Time Points'
set ylabel 'Correlation Coefficient'
set grid
set style rect fc rgb 'yellow' fs transparent solid 0.2
set object rectangle from 8,graph 0 to 35,graph 1
# Note: This requires correlation_time_series.dat to be generated
# plot 'correlation_time_series.dat' using 1:2 with lines lw 3 title 'Correct Key 0xEA'

set title 'UBlock CPA Attack - First 32 Key Guesses (Fixed)'
set xlabel 'Key Guess'
set ylabel 'Max Correlation'
set xrange [-0.5:31.5]
unset object
plot 'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==0?$1:1/0):2 with impulses lc rgb "#87CEEB" lw 3 title 'Wrong Keys', \
     'ublock_cpa_byte_attack.dat' using ($1<=31 && $4==1?$1:1/0):2 with impulses lc rgb "red" lw 5 title 'Correct Key'

