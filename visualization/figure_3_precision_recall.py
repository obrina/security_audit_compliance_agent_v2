#!/usr/bin/env python3
"""
Figure 3: Precision-Recall Trade-off
Visualizes the precision-recall-faithfulness triangle across methods
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Set publication-quality style
plt.rcParams['font.family'] = 'Arial'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.linewidth'] = 1.5
plt.rcParams['figure.dpi'] = 300

# Colorblind-friendly palette
COLORS = {
    'Rule-based': '#0173B2',
    'Vector RAG': '#DE8F05',
    'Graph RAG': '#029E73'
}

# Method name mapping for clean display
METHOD_LABELS = {
    'Rule-based': 'Rule-based\n(F=0.524)',
    'Vector RAG': 'Vector RAG\n(F=0.509)',
    'Graph RAG': 'Graph RAG\n(F=0.570)'
}

def load_data():
    """Load filtered results for all 3 methods"""
    rule = pd.read_csv('../results/heuristic_baseline_results_filtered.csv')
    vector = pd.read_csv('../results/vector_rag_compliance_results_filtered.csv')
    graph = pd.read_csv('../results/lightrag_compliance_results_FINAL.csv')

    return {
        'Rule-based': rule,
        'Vector RAG': vector,
        'Graph RAG': graph
    }

def compute_metrics(data):
    """Compute mean precision, recall, faithfulness per method"""
    results = []

    for method_name, df in data.items():
        results.append({
            'Method': method_name,
            'Precision': df['context_precision'].dropna().mean(),
            'Recall': df['context_recall'].dropna().mean(),
            'Faithfulness': df['faithfulness'].dropna().mean()
        })

    return pd.DataFrame(results)

def create_figure(metrics_df):
    """Create publication-quality scatter plot"""
    # Even larger figure for better readability
    fig, ax = plt.subplots(figsize=(16/2.54, 11/2.54))

    # Plot each method with distinct sizes
    sizes = {'Rule-based': 1000, 'Vector RAG': 1200, 'Graph RAG': 1400}

    for _, row in metrics_df.iterrows():
        method = row['Method']
        precision = row['Precision']
        recall = row['Recall']

        ax.scatter(recall, precision, s=sizes[method],
                   color=COLORS[method], alpha=0.75,
                   edgecolors='black', linewidths=2.5,
                   label=METHOD_LABELS[method],
                   zorder=3)

    # Carefully position annotations to avoid ALL overlaps
    # Rule-based: (0.124, 0.814) - position ABOVE
    rule_row = metrics_df[metrics_df['Method'] == 'Rule-based'].iloc[0]
    ax.annotate('Lowest\nrecall\n(0.124)',
                xy=(rule_row['Recall'], rule_row['Precision']),
                xytext=(rule_row['Recall'] + 0.025, rule_row['Precision'] + 0.06),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='black'),
                fontsize=11,
                bbox=dict(boxstyle='round,pad=0.6', facecolor='#0173B2',
                         edgecolor='black', alpha=0.3, linewidth=1.5),
                zorder=4)

    # Vector RAG: (0.224, 0.856) - position to the RIGHT with good separation
    vector_row = metrics_df[metrics_df['Method'] == 'Vector RAG'].iloc[0]
    ax.annotate('Highest\nrecall\n(0.224)',
                xy=(vector_row['Recall'], vector_row['Precision']),
                xytext=(vector_row['Recall'] + 0.012, vector_row['Precision'] + 0.04),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='black'),
                fontsize=11,
                bbox=dict(boxstyle='round,pad=0.6', facecolor='#DE8F05',
                         edgecolor='black', alpha=0.3, linewidth=1.5),
                zorder=4)

    # Graph RAG: (0.189, 0.996) - position well to the LEFT and BELOW with separation
    graph_row = metrics_df[metrics_df['Method'] == 'Graph RAG'].iloc[0]
    ax.annotate('Near-perfect\nprecision\n(0.996)',
                xy=(graph_row['Recall'], graph_row['Precision']),
                xytext=(graph_row['Recall'] - 0.070, graph_row['Precision'] - 0.060),
                arrowprops=dict(arrowstyle='->', lw=2.5, color='black'),
                fontsize=11,
                bbox=dict(boxstyle='round,pad=0.6', facecolor='#029E73',
                         edgecolor='black', alpha=0.3, linewidth=1.5),
                zorder=4)

    # Formatting with larger fonts
    ax.set_xlabel('Context Recall', fontsize=14, fontweight='bold', labelpad=8)
    ax.set_ylabel('Context Precision', fontsize=14, fontweight='bold', labelpad=8)

    # Extended axis limits to provide space for annotations
    ax.set_xlim(0.10, 0.28)
    ax.set_ylim(0.78, 1.04)

    # Position legend OUTSIDE the plot area on the right side
    ax.legend(loc='center left', frameon=True, fontsize=11,
             title='Method (Faithfulness)', title_fontsize=11,
             framealpha=0.95, edgecolor='black', fancybox=False,
             borderpad=0.8, labelspacing=0.8,
             bbox_to_anchor=(1.02, 0.5))

    # Grid
    ax.grid(alpha=0.3, linestyle='--', linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    # Larger tick labels with better formatting
    ax.tick_params(axis='both', labelsize=12, width=1.5, length=6, pad=6)

    # Format tick labels to 2 decimal places
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{x:.2f}'))
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, p: f'{y:.2f}'))

    plt.tight_layout(pad=1.2)
    return fig

def main():
    print("Generating Figure 3: Precision-Recall Trade-off...")

    # Load data
    data = load_data()
    print(f"✓ Loaded data: {sum(len(df) for df in data.values())} total evaluations")

    # Compute metrics
    metrics_df = compute_metrics(data)
    print(f"✓ Computed metrics for 3 methods")

    # Create figure
    fig = create_figure(metrics_df)

    # Save
    fig.savefig('figure_3_precision_recall.png', dpi=300, bbox_inches='tight')
    fig.savefig('figure_3_precision_recall.pdf', bbox_inches='tight')
    print("✓ Saved: figure_3_precision_recall.png (300 DPI)")
    print("✓ Saved: figure_3_precision_recall.pdf")

    # Save data
    metrics_df.to_csv('figure_3_metrics.csv', index=False)
    print("✓ Saved: figure_3_metrics.csv")

    # Print summary
    print("\n" + "="*60)
    print("PRECISION-RECALL TRADE-OFF SUMMARY")
    print("="*60)
    print(metrics_df.to_string(index=False))

    # Compute F1 scores
    print("\n" + "="*60)
    print("HARMONIC MEANS (F1 SCORES)")
    print("="*60)
    for _, row in metrics_df.iterrows():
        precision = row['Precision']
        recall = row['Recall']
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        print(f"{row['Method']:15s}: F1={f1:.4f} (P={precision:.3f}, R={recall:.3f})")

    # Key insight
    print("\n" + "="*60)
    print("KEY INSIGHT")
    print("="*60)
    graph_row = metrics_df[metrics_df['Method'] == 'Graph RAG'].iloc[0]
    rule_row = metrics_df[metrics_df['Method'] == 'Rule-based'].iloc[0]

    print(f"Graph RAG achieves {graph_row['Recall']/rule_row['Recall']:.1f}× higher recall")
    print(f"than Rule-based while maintaining high precision ({graph_row['Precision']:.3f}).")
    print(f"Combined with {graph_row['Faithfulness']:.3f} faithfulness, this represents")
    print(f"the optimal balance for compliance analysis.")

if __name__ == "__main__":
    main()
