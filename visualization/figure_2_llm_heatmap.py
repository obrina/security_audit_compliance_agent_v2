#!/usr/bin/env python3
"""
Figure 2: Faithfulness by LLM and Method
Shows consistency of Graph RAG superiority across all 4 LLMs
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Set publication-quality style
plt.rcParams['font.family'] = 'Arial'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.linewidth'] = 1.5
plt.rcParams['figure.dpi'] = 300

# Colorblind-friendly palette
COLORS = {
    'Rule-based': '#0173B2',
    'Vector RAG': '#DE8F05',
    'Graph RAG': '#029E73'
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

def compute_llm_faithfulness(data):
    """Compute mean faithfulness per LLM per method"""
    results = []

    # LLM name mapping (standardize names from CSV)
    llm_map = {
        'DeepSeek-R1-8B (Local)': 'DeepSeek-R1',
        'Qwen-2.5-7B (Local)': 'Qwen-2.5',
        'Llama-3.2-3B (Local)': 'Llama-3.2',
        'GPT-4o-mini (OpenAI)': 'GPT-4o-mini'
    }

    for method_name, df in data.items():
        for llm_full, llm_short in llm_map.items():
            # Filter for this LLM (column is 'llm' not 'llm_name')
            llm_data = df[df['llm'] == llm_full]['faithfulness'].dropna()

            if len(llm_data) > 0:
                results.append({
                    'Method': method_name,
                    'LLM': llm_short,
                    'Faithfulness': llm_data.mean()
                })

    return pd.DataFrame(results)

def create_heatmap(faithfulness_df):
    """Create publication-quality heatmap"""
    # Pivot for heatmap
    pivot = faithfulness_df.pivot(index='LLM', columns='Method', values='Faithfulness')

    # Reorder columns
    pivot = pivot[['Rule-based', 'Vector RAG', 'Graph RAG']]

    # Remove GPT-4o-mini row if it exists and has no data (all NaN)
    if 'GPT-4o-mini' in pivot.index and pivot.loc['GPT-4o-mini'].isna().all():
        pivot = pivot.drop('GPT-4o-mini')

    # Reorder rows (largest to smallest model) - only keep rows with data
    row_order = ['DeepSeek-R1', 'Qwen-2.5', 'Llama-3.2']
    pivot = pivot.reindex([r for r in row_order if r in pivot.index])

    # Create figure with more horizontal space
    fig, ax = plt.subplots(figsize=(14/2.54, 7/2.54))  # Increased width for better label spacing

    # Create heatmap with custom colormap
    cmap = sns.diverging_palette(10, 130, s=80, l=55, as_cmap=True)
    sns.heatmap(pivot, annot=True, fmt='.3f', cmap=cmap,
                vmin=0.30, vmax=0.65,  # Adjusted range based on actual data
                cbar_kws={'label': 'Faithfulness Score'},
                linewidths=0.5, linecolor='gray',
                annot_kws={'fontsize': 9},
                ax=ax)

    # Formatting
    ax.set_xlabel('Method', fontsize=10, fontweight='bold')
    ax.set_ylabel('LLM', fontsize=10, fontweight='bold')

    # Fix x-axis labels with better spacing
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0, ha='center', fontsize=9)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=9)

    # Add tick padding to prevent label overlap
    ax.tick_params(axis='x', pad=4)
    ax.tick_params(axis='y', pad=2)

    plt.tight_layout(pad=1.5)  # More breathing room around edges
    return fig, pivot

def create_grouped_bars(faithfulness_df):
    """Alternative: grouped bar chart"""
    fig, ax = plt.subplots(figsize=(12/2.54, 7/2.54))

    # Filter out GPT-4o-mini if it has no data
    llms = [llm for llm in ['DeepSeek-R1', 'Qwen-2.5', 'Llama-3.2']
            if llm in faithfulness_df['LLM'].unique()]
    methods = ['Rule-based', 'Vector RAG', 'Graph RAG']

    x = np.arange(len(llms))
    width = 0.25

    for i, method in enumerate(methods):
        method_data = faithfulness_df[faithfulness_df['Method'] == method]
        values = [method_data[method_data['LLM'] == llm]['Faithfulness'].values[0]
                  for llm in llms]

        ax.bar(x + i*width, values, width,
               label=method,
               color=COLORS[method])

    # Formatting
    ax.set_ylabel('Faithfulness Score', fontsize=10, fontweight='bold')
    ax.set_xlabel('LLM', fontsize=10, fontweight='bold')
    ax.set_xticks(x + width)
    ax.set_xticklabels(llms, fontsize=9)
    ax.set_ylim(0.30, 0.65)
    ax.legend(loc='upper right', frameon=True, fontsize=8)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    plt.tight_layout()
    return fig

def main():
    print("Generating Figure 2: Faithfulness by LLM and Method...")

    # Load data
    data = load_data()
    print(f"✓ Loaded data: {sum(len(df) for df in data.values())} total evaluations")

    # Compute LLM × Method faithfulness
    faithfulness_df = compute_llm_faithfulness(data)
    print(f"✓ Computed faithfulness for {len(faithfulness_df)} LLM × Method combinations")

    # Create both visualizations
    fig_heatmap, pivot = create_heatmap(faithfulness_df)
    fig_bars = create_grouped_bars(faithfulness_df)

    # Save heatmap
    fig_heatmap.savefig('figure_2_llm_heatmap.png', dpi=300, bbox_inches='tight')
    fig_heatmap.savefig('figure_2_llm_heatmap.pdf', bbox_inches='tight')
    print("✓ Saved: figure_2_llm_heatmap.png (300 DPI)")
    print("✓ Saved: figure_2_llm_heatmap.pdf")

    # Save grouped bars (alternative)
    fig_bars.savefig('figure_2_llm_bars.png', dpi=300, bbox_inches='tight')
    fig_bars.savefig('figure_2_llm_bars.pdf', bbox_inches='tight')
    print("✓ Saved: figure_2_llm_bars.png (300 DPI)")
    print("✓ Saved: figure_2_llm_bars.pdf (alternative)")

    # Save data to CSV
    faithfulness_df.to_csv('figure_2_faithfulness_by_llm.csv', index=False)
    pivot.to_csv('figure_2_heatmap_data.csv')
    print("✓ Saved: figure_2_faithfulness_by_llm.csv")
    print("✓ Saved: figure_2_heatmap_data.csv")

    # Print summary
    print("\n" + "="*60)
    print("LLM × METHOD FAITHFULNESS SUMMARY")
    print("="*60)
    print(pivot.to_string())

    # Consistency analysis
    print("\n" + "="*60)
    print("CONSISTENCY ANALYSIS")
    print("="*60)
    for method in ['Rule-based', 'Vector RAG', 'Graph RAG']:
        method_data = faithfulness_df[faithfulness_df['Method'] == method]['Faithfulness']
        std = method_data.std()
        cv = (std / method_data.mean()) * 100  # Coefficient of variation
        print(f"{method:15s}: StdDev={std:.4f}, CV={cv:.1f}%")

    # Best performer per LLM
    print("\n" + "="*60)
    print("BEST METHOD PER LLM")
    print("="*60)
    for llm in pivot.index:
        best_method = pivot.loc[llm].idxmax()
        best_score = pivot.loc[llm].max()
        if pd.isna(best_method) or pd.isna(best_score):
            print(f"{llm:15s}: No data available")
        else:
            print(f"{llm:15s}: {best_method:15s} ({best_score:.3f})")

if __name__ == "__main__":
    main()
