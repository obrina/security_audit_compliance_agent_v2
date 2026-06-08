#!/usr/bin/env python3
"""
Figure 4: Per-Attack Class Faithfulness (Corrected Grouped Bar Chart)
Replaces the old radar chart with proper class grouping.
Provision 5.7 classes (Backdoor, DDoS, DoS, Benign) grouped as 'Malware/DoS'.
"""
import matplotlib.pyplot as plt
import numpy as np

# Corrected data (from _fix_attack_class_data.py)
ORDER = ['BruteForce', 'WebBased', 'Spoofing', 'Recon', 'Malware/DoS']

DATA = {
    'Rule-based': [0.763, 0.526, 0.326, 0.298, 0.565],
    'Vector RAG': [0.619, 0.320, 0.635, 0.826, 0.293],
    'Graph RAG':  [0.598, 0.489, 0.261, 0.739, 0.653]
}

CV = {
    'Rule-based': 38.4,
    'Vector RAG': 42.1,
    'Graph RAG':  33.7
}

COLORS = {'Rule-based': '#0173B2', 'Vector RAG': '#DE8F05', 'Graph RAG': '#029E73'}

# Set publication-quality style
plt.rcParams['font.family'] = 'Arial'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.linewidth'] = 1.5
plt.rcParams['figure.dpi'] = 300

fig, ax = plt.subplots(figsize=(18/2.54, 11/2.54))

x = np.arange(len(ORDER))
width = 0.25

for i, (method, values) in enumerate(DATA.items()):
    offset = (i - 1) * width
    bars = ax.bar(x + offset, values, width,
                  color=COLORS[method], alpha=0.85,
                  edgecolor='black', linewidth=1.5,
                  label=f"{method} (CV={CV[method]:.1f}%)",
                  zorder=3)
    
    # Add value labels on bars
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.02,
                f'{val:.3f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

# Labels and formatting
ax.set_xlabel('Attack Class', fontsize=12, labelpad=8)
ax.set_ylabel('Mean Faithfulness', fontsize=12, labelpad=8)
ax.set_title('Faithfulness by Attack Class and Retrieval Method', fontsize=13, pad=10)
ax.set_xticks(x)
ax.set_xticklabels(ORDER, fontsize=10)
ax.set_ylim(0, 1.0)
ax.set_yticks(np.arange(0, 1.1, 0.1))
ax.yaxis.set_major_formatter(plt.FixedFormatter([f'{tick:.1f}' for tick in np.arange(0, 1.1, 0.1)]))
ax.legend(fontsize=10, framealpha=0.9, edgecolor='black', loc='upper left')
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.axhline(y=0.5, color='red', linestyle=':', alpha=0.5, linewidth=1.5,
           label='Faithfulness=0.5 threshold')

plt.tight_layout(pad=1.2)
fig.savefig('figure_4_attack_class_bars.png', dpi=300, bbox_inches='tight')
fig.savefig('figure_4_attack_class_bars.pdf', bbox_inches='tight')
print("Saved: figure_4_attack_class_bars.png/pdf")

# Print summary
print(f"\nCV comparison:")
print(f"  Rule-based: CV={CV['Rule-based']:.1f}%")
print(f"  Vector RAG: CV={CV['Vector RAG']:.1f}%")
print(f"  Graph RAG:  CV={CV['Graph RAG']:.1f}%  ← best")
print(f"\nGraph RAG range: {min(DATA['Graph RAG']):.3f} to {max(DATA['Graph RAG']):.3f}")
print(f"Rule-based range: {min(DATA['Rule-based']):.3f} to {max(DATA['Rule-based']):.3f}")
print(f"Vector RAG range: {min(DATA['Vector RAG']):.3f} to {max(DATA['Vector RAG']):.3f}")
