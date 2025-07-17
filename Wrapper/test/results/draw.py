# import pandas as pd
# import seaborn as sns
# import matplotlib.pyplot as plt

# data = {
#     'Executable': [
#         'execution_backdoor_adv', 'execution_backdoor_adv',
#         'recon_privsec_adv', 'recon_privsec_adv',
#         'CWE78_s01', 'CWE78_s01'
#     ],
#     'Tracing Method': [
#         'strace', 'monitor.bt(x86)', 'monitor.bt(riscv)',
#         'strace', 'monitor.bt(x86)', 'monitor.bt(riscv)',
#         'strace', 'monitor.bt(x86)' 'monitor.bt(riscv)',
#     ],
#     'Average Time': [
#         0.03437922729222346, 0.012603517107129973,
#         0.06033313964749179, 0.037768739105171555,
#         0.1327988846287906, 0.12303938654583478

#     ]
# }
# df = pd.DataFrame(data)

# sns.set_theme(style="whitegrid")

# plt.rcParams['axes.unicode_minus'] = False 

# fig, ax = plt.subplots(figsize=(12, 7))

# sns.barplot(
#     data=df,
#     x='Executable',
#     y='Average Time',
#     hue='Tracing Method',
#     ax=ax,
#     palette='viridis' 
# )

# ax.set_xlabel('Executable Under Test', fontsize=12)
# ax.set_ylabel('Overhead', fontsize=12)

# ax.legend(title='Tracing Method', title_fontsize='13', fontsize='11')

# plt.tight_layout()

# output_filename = 'timing_comparison_chart.png'
# plt.savefig(output_filename)

# print(f"picture saved as '{output_filename}'")
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# --- 数据部分 ---
data = {
    'Executable': [
        'execution_backdoor_adv', 'execution_backdoor_adv', 'execution_backdoor_adv',
        'recon_privsec_adv', 'recon_privsec_adv', 'recon_privsec_adv',
        'CWE78_s01', 'CWE78_s01', 'CWE78_s01'
    ],
    'Tracing Method': [
        'strace', 'monitor.bt(x86)', 'monitor.bt(riscv)',
        'strace', 'monitor.bt(x86)', 'monitor.bt(riscv)',
        'strace', 'monitor.bt(x86)', 'monitor.bt(riscv)'
    ],
    'Average Time': [
        1.69, 1.07, 2.30,
        0.55, 0.79, 3.07,
        17.92, 15.34, 61.53
    ]
}
df = pd.DataFrame(data)

# --- 主题与风格设置 ---
sns.set_theme(style="ticks", font_scale=1.1)
plt.rcParams['axes.unicode_minus'] = False
fig, ax = plt.subplots(figsize=(14, 8))

# --- 绘制条形图 ---
sns.barplot(
    data=df,
    x='Executable',
    y='Average Time',
    hue='Tracing Method',
    ax=ax,
    palette='viridis',  # 使用柔和的色调
    edgecolor=".2"
)

# --- 添加数据标签 ---
for p in ax.patches:
    ax.annotate(
        format(p.get_height(), '.2f'),
        (p.get_x() + p.get_width() / 2., p.get_height()),
        ha = 'center', va = 'center',
        xytext = (0, 9),
        textcoords = 'offset points',
        fontsize=11,
        color='dimgray'
    )

# --- 优化坐标轴标签 (无标题) ---
ax.set_xlabel(
    'ELF Under Test',
    fontsize=14,
    fontweight='bold', # 加粗
    labelpad=20, # 增加标签与轴的间距
    color='#333333' # 使用深灰色，比纯黑更柔和
)
ax.set_ylabel(
    'Overhead(%)',
    fontsize=14,
    fontweight='bold', # 加粗
    labelpad=20, # 增加标签与轴的间距
    color='#333333' # 使用深灰色
)

# --- 图例与最终润色 ---
ax.legend(title='Tracing Method', title_fontsize='13', fontsize='12', frameon=False)
ax.set_ylim(0, df['Average Time'].max() * 1.15)
sns.despine()
plt.tight_layout()

# --- 保存图片 ---
output_filename = 'timing_comparison_chart_final.png'
plt.savefig(output_filename, dpi=300)

print(f"picture saved as '{output_filename}'")