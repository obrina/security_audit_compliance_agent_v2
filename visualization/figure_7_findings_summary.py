"""
Figure 7: Comprehensive Findings Summary
Multi-panel visualization showing:
  (A) Faithfulness comparison with error bars
  (B) Stability analysis (CV across LLMs vs Attack Classes)
  (C) Precision-Recall scatter with faithfulness bubble
  (D) Multi-metric radar chart

All data sourced from the final corrected manuscript values (May 2026).
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch
from matplotlib.lines import Line2D
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ============================================================
# STYLE CONFIGURATION
# ============================================================
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif'],
    'font.size': 10,
    'axes.titlesize': 12,
    'axes.labelsize': 10,
    'legend.fontsize': 8,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'axes.edgecolor': '#333333',
    'axes.linewidth': 0.8,
})

# Colour palette (colourblind-friendly)
C_RULE = '#4C72B0'    # blue
C_VECTOR = '#DD8452'  # orange  
C_GRAPH = '#55A868'   # green
C_LLM = '#C44E52'     # red for LLM axis

# ============================================================
# DATA
# ============================================================
methods = ['Rule-based', 'Vector RAG', 'Graph RAG']
methods_short = ['Rule', 'Vector', 'Graph']
x = np.arange(len(methods))

# Panel A: Faithfulness ± std dev
faith_mean  = [0.524, 0.509, 0.570]
faith_std   = [0.271, 0.308, 0.313]
faith_ci95  = [0.060, 0.070, 0.058]  # 95% CI from manuscript

# Panel B: CV (%)
cv_llm   = [9.1,  21.5, 10.1]   # across LLMs
cv_attack= [38.4, 42.1, 33.7]   # across attack classes

# Panel C: Precision-Recall
prec = [0.814, 0.856, 0.996]
rec  = [0.124, 0.224, 0.189]
bubble_size = [180, 160, 280]  # proportional to faithfulness

# Panel D: Radar - all 5 RAGAS metrics
metrics_labels = ['Faithfulness', 'Context\nPrecision', 'Context\nRecall', 'Answer\nCorrectness', 'Answer\nRelevancy']
# Normalise to 0-1 scale (already 0-1)
rule_radar = [0.524, 0.814, 0.124, 0.349, 0.570]
vec_radar  = [0.509, 0.856, 0.224, 0.399, 0.579]
graph_radar= [0.570, 0.996, 0.189, 0.360, 0.645]

# ============================================================
# BUILD FIGURE
# ============================================================
fig = plt.figure(figsize=(14, 10))
gs = GridSpec(2, 2, figure=fig, hspace=0.35, wspace=0.30,
              left=0.07, right=0.95, bottom=0.08, top=0.92)

# ---- PANEL A: Faithfulness Bar Chart ----
ax1 = fig.add_subplot(gs[0, 0])
bars = ax1.bar(x, faith_mean, width=0.55, 
               color=[C_RULE, C_VECTOR, C_GRAPH],
               edgecolor='white', linewidth=1.2,
               zorder=3)

# Add error bars (95% CI)
for i, (mean, ci) in enumerate(zip(faith_mean, faith_ci95)):
    ax1.errorbar(i, mean, yerr=ci, fmt='none',
                 ecolor='#333333', capsize=6, capthick=1.5,
                 elinewidth=1.5, zorder=4)

# Add value labels on bars
for i, (mean, std) in enumerate(zip(faith_mean, faith_std)):
    ax1.text(i, mean + 0.018, f'{mean:.3f}', 
             ha='center', va='bottom', fontsize=11, fontweight='bold',
             color='#333333')

# Annotation bracket for non-significance
y_ns = 0.72
ax1.annotate('', xy=(0.2, y_ns), xytext=(2.8, y_ns),
             arrowprops=dict(arrowstyle='-', color='#888888', lw=1.5))
ax1.text(1.5, y_ns + 0.015, 'ANOVA $p = 0.35$\nCohen\'s $d < 0.2$',
         ha='center', va='bottom', fontsize=8, color='#888888',
         fontstyle='italic')

# Labels & style
ax1.set_xticks(x)
ax1.set_xticklabels(methods, fontsize=11)
ax1.set_ylabel('Faithfulness Score', fontsize=11)
ax1.set_title('(A) Explanation Faithfulness by Retrieval Method', 
              fontsize=12, fontweight='bold', pad=8)
ax1.set_ylim(0, 0.82)
ax1.grid(axis='y', alpha=0.3, linestyle='--', zorder=1)
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)

# Inset: "over 40% statements unsupported" callout
ax1.annotate('', xy=(0.2, 0.06), xytext=(2.8, 0.06),
             arrowprops=dict(arrowstyle='-', color=C_LLM, lw=2, 
                             linestyle='dotted'))
ax1.text(1.5, 0.0, 'Over 40% of LLM statements\nunsupported by evidence',
         ha='center', va='top', fontsize=8, color=C_LLM, fontstyle='italic')


# ---- PANEL B: Coefficient of Variation (Stability) ----
ax2 = fig.add_subplot(gs[0, 1])
x2 = np.arange(len(methods))
width = 0.30

bars_llm = ax2.bar(x2 - width/2, cv_llm, width, label='Across LLMs',
                   color=C_LLM, edgecolor='white', linewidth=1, zorder=3)
bars_att = ax2.bar(x2 + width/2, cv_attack, width, 
                   label='Across Attack Classes',
                   color='#8B5A2B', edgecolor='white', linewidth=1, zorder=3)

# Add value labels
for bar in bars_llm:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
             f'{bar.get_height():.1f}%', ha='center', va='bottom',
             fontsize=9, fontweight='bold', color=C_LLM)
for bar in bars_att:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
             f'{bar.get_height():.1f}%', ha='center', va='bottom',
             fontsize=9, fontweight='bold', color='#8B5A2B')

# Annotation: lower is better
ax2.text(0.97, 0.95, 'Lower CV = More Stable', 
         transform=ax2.transAxes, fontsize=8, color='#666666',
         ha='right', fontstyle='italic')

ax2.set_xticks(x2)
ax2.set_xticklabels(methods, fontsize=11)
ax2.set_ylabel('Coefficient of Variation (%)', fontsize=11)
ax2.set_title('(B) Stability Across Dimensions', 
              fontsize=12, fontweight='bold', pad=8)
ax2.set_ylim(0, 55)
ax2.grid(axis='y', alpha=0.3, linestyle='--', zorder=1)
ax2.legend(frameon=True, fancybox=True, fontsize=9, loc='upper left')
ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)


# ---- PANEL C: Precision-Recall Bubble ----
ax3 = fig.add_subplot(gs[1, 0])
scatter_colors = [C_RULE, C_VECTOR, C_GRAPH]
edge_colors = ['#2c3e50', '#2c3e50', '#2c3e50']

scatters = []
for i in range(3):
    s = ax3.scatter(rec[i], prec[i], s=bubble_size[i], 
                    c=scatter_colors[i], edgecolors=edge_colors[i],
                    linewidths=1.5, zorder=4, alpha=0.85)
    scatters.append(s)

# Add labels
offsets = [(10, -25), (-15, 25), (10, 20)]
for i, (r, p) in enumerate(zip(rec, prec)):
    ax3.annotate(methods[i], (r, p),
                 xytext=offsets[i], textcoords='offset points',
                 fontsize=10, fontweight='bold',
                 ha='center', va='bottom' if i != 0 else 'top',
                 color=scatter_colors[i])

# Add quadrant lines
ax3.axhline(y=0.90, color='#cccccc', linestyle=':', linewidth=1, zorder=1)
ax3.axvline(x=0.15, color='#cccccc', linestyle=':', linewidth=1, zorder=1)

# Annotation: ideal quadrant
ax3.text(0.25, 0.94, 'Ideal:\nHigh Precision\nHigh Recall', 
         fontsize=7, color='#aaaaaa', fontstyle='italic', ha='center')

# Legend for bubble size
legend_elements = [
    Line2D([0], [0], marker='o', color='w', markerfacecolor='#888888',
           markersize=10, label='Faithfulness = 0.51'),
    Line2D([0], [0], marker='o', color='w', markerfacecolor='#888888',
           markersize=14, label='Faithfulness = 0.57'),
]
ax3.legend(handles=legend_elements, loc='lower left', fontsize=8,
           title='Bubble Size ~ Faithfulness', title_fontsize=8, framealpha=0.9)

ax3.set_xlabel('Context Recall', fontsize=11)
ax3.set_ylabel('Context Precision', fontsize=11)
ax3.set_title('(C) Precision–Recall Trade-off', 
              fontsize=12, fontweight='bold', pad=8)
ax3.set_xlim(0.05, 0.30)
ax3.set_ylim(0.70, 1.05)
ax3.grid(alpha=0.3, linestyle='--', zorder=1)
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)


# ---- PANEL D: Radar Chart ----
ax4 = fig.add_subplot(gs[1, 1], projection='polar')
num_vars = len(metrics_labels)
angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
angles += angles[:1]  # close the circle

def radar_fill(ax, data, color, label, alpha=0.15):
    values = data + data[:1]
    ax.plot(angles, values, 'o-', linewidth=2, color=color, label=label, 
            markersize=5)
    ax.fill(angles, values, alpha=alpha, color=color)

radar_fill(ax4, rule_radar, C_RULE, 'Rule-based')
radar_fill(ax4, vec_radar, C_VECTOR, 'Vector RAG')
radar_fill(ax4, graph_radar, C_GRAPH, 'Graph RAG')

ax4.set_xticks(angles[:-1])
ax4.set_xticklabels(metrics_labels, fontsize=9)
ax4.set_ylim(0, 1.0)
ax4.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
ax4.set_yticklabels(['0.2', '0.4', '0.6', '0.8', '1.0'], fontsize=7)
ax4.set_title('(D) Multi-Metric Profile (All RAGAS Metrics)', 
              fontsize=12, fontweight='bold', pad=20)
ax4.legend(loc='lower right', fontsize=8, framealpha=0.9, 
           bbox_to_anchor=(1.3, -0.05))

# Add subtle circular grid
ax4.grid(True, alpha=0.3, linestyle='--')

# ============================================================
# MAIN TITLE & FOOTER
# ============================================================
fig.suptitle('Summary of Experimental Findings',
             fontsize=16, fontweight='bold', y=0.98)

# Footer note
fig.text(0.5, 0.01, 
         'Data source: Corrected manuscript values (May 2026) — 30 expert-validated scenarios, 3 LLMs, RAGAS evaluation with Gemini 2.5 Flash',
         ha='center', fontsize=7, color='#888888', fontstyle='italic')

# ============================================================
# SAVE
# ============================================================
output_path = 'visualization/figure_7_findings_summary.png'
fig.savefig(output_path, dpi=300, bbox_inches='tight', 
            facecolor='white', edgecolor='none')
print(f'Saved: {output_path}')

# Also save PDF
output_pdf = output_path.replace('.png', '.pdf')
fig.savefig(output_pdf, dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
print(f'Saved: {output_pdf}')

plt.close()
