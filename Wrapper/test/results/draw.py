import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

data = {
    'Executable': [
        'execution_backdoor_adv', 'execution_backdoor_adv', 'execution_backdoor_adv',
        'recon_privsec_adv', 'recon_privsec_adv', 'recon_privsec_adv',
        'CWE78_s01', 'CWE78_s01', 'CWE78_s01'
    ],
    'Tracing Method': [
        'Baseline', 'strace', 'monitor.bt',
        'Baseline', 'strace', 'monitor.bt',
        'Baseline', 'strace', 'monitor.bt'
    ],
    'Average Time': [
        3.0309, 3.1351, 3.0691,  
        1.0326, 1.0949, 1.0716,  
        0.2869, 0.3250, 0.3222  
    ]
}
df = pd.DataFrame(data)

sns.set_theme(style="whitegrid")

plt.rcParams['axes.unicode_minus'] = False 

fig, ax = plt.subplots(figsize=(12, 7))

sns.barplot(
    data=df,
    x='Executable',
    y='Average Time',
    hue='Tracing Method',
    ax=ax,
    palette='viridis' 
)

ax.set_title('Comparing Running Time with Tracing Method', fontsize=16, pad=20)
ax.set_xlabel('Executable Under Test', fontsize=12)
ax.set_ylabel('Average Time(s)', fontsize=12)

ax.legend(title='Tracing Method', title_fontsize='13', fontsize='11')

plt.tight_layout()

output_filename = 'timing_comparison_chart.png'
plt.savefig(output_filename)

print(f"picture saved as '{output_filename}'")