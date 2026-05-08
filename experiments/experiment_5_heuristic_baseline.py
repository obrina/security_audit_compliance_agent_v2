#!/usr/bin/env python3
"""
Experiment 5: Rule-Based Heuristic Scoring

Paper: "Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"
Authors: Obrina Briliyant, Amir Javed, Yulia Cherdantseva
Affiliation: Cardiff University

Description:
    Implements NetTraceAgentix-inspired heuristic anomaly scoring adapted for 
    flow-level features. Evaluates compliance explanations without semantic retrieval.

Usage:
    python experiment_5_heuristic_baseline.py

Requirements:
    - compliance_ground_truth.json in data/
    - CIC-IoT2023 test dataset (df_class_8_test.csv)
    - Environment variables: OPENROUTER_API_KEY, GOOGLE_API_KEY
"""
import os
import json
import pandas as pd
import numpy as np
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv()
BASE_PATH = '/home/abyasa/Documents/mdpi_experiment'

# ═══════════════════════════════════════════════════════════════════════════
# 1. Load Ground Truth and Flow Features
# ═══════════════════════════════════════════════════════════════════════════

with open(f'{BASE_PATH}/compliance_ground_truth.json', 'r') as f:
    ground_truth = json.load(f)

print(f"✓ Loaded {len(ground_truth)} ground-truth scenarios")

# ═══════════════════════════════════════════════════════════════════════════
# 2. Define Heuristic Anomaly Scoring (NetTraceAgentix-inspired)
# ═══════════════════════════════════════════════════════════════════════════

def calculate_anomaly_score(features: Dict[str, Any], attack_class: str) -> float:
    """
    Rule-based anomaly scoring using CIC-IoT2023 flow features.
    Inspired by NetTraceAgentix's heuristic weights.

    NetTraceAgentix weights (packet-level):
    - malformed: 15
    - suspicious-flags: 12
    - fragment: 12
    - rst: 10
    - retransmission: 8
    - checksum-error: 5

    Our adaptation (flow-level features):
    """
    score = 0.0

    # High retransmission/ACK activity (proxy for packet loss/retrans)
    if features.get('Rolling_ACK_Sum', 0) > 300:
        score += 8

    # Abnormal SYN activity (SYN flood, port scan)
    if features.get('Rolling_SYN_Sum', 0) > 300:
        score += 12

    # UDP bursts (DDoS/Spoofing indicator)
    udp_sum = features.get('Rolling_UDP_Sum', 0)
    if udp_sum > 1000:
        score += 10
    elif udp_sum > 200:
        score += 6  # Moderate UDP activity

    # High packet count (potential flood)
    if features.get('src2dst_packets', 0) > 5000:
        score += 6

    # High byte count (data exfiltration or DDoS)
    if features.get('src2dst_bytes', 0) > 1000000:
        score += 5

    # Unusual ports (outside common ranges)
    unique_ports = features.get('Unique_Ports', 0)
    if unique_ports > 10:  # Port scanning indicator
        score += 10
    elif unique_ports == 1 and features.get('dst2src_packets', 0) == 0:
        score += 8  # Unidirectional + single port = suspicious

    # Packet size variation (fragmentation, evasion)
    pkt_var = features.get('packet_size_variation', 0)
    if pkt_var > 1.5:  # High variation
        score += 7
    elif pkt_var < 0.1:  # Very uniform (scripted attack)
        score += 5

    # Mean packet size extremes
    mean_ps = features.get('bidirectional_mean_ps', 0)
    if mean_ps < 100:  # Very small packets (protocol abuse)
        score += 6
    elif mean_ps > 1400:  # Very large packets (fragmentation)
        score += 6

    # Attack class boosting (domain knowledge)
    class_weights = {
        'DDoS': 1.3,      # DDoS has clear flow anomalies
        'DoS': 1.3,
        'Recon': 1.3,     # Port scans have pattern anomalies (boosted)
        'Spoofing': 1.5,  # ARP/DNS spoofing = high anomaly (boosted)
        'Backdoor': 1.1,  # Backdoors are stealthier
        'BruteForce': 1.2,
        'WebBased': 1.0,  # Web attacks less flow-obvious
        'Benign': 0.5     # Downweight benign
    }

    multiplier = class_weights.get(attack_class, 1.0)
    return score * multiplier


# ═══════════════════════════════════════════════════════════════════════════
# 3. Heuristic Retrieval: Rank Flows by Anomaly Score
# ═══════════════════════════════════════════════════════════════════════════

def retrieve_by_heuristic(question: str, ground_truth: List[Dict], top_k: int = 5) -> List[str]:
    """
    Retrieve contexts using rule-based anomaly scoring (NOT embeddings).
    Simulates NetTraceAgentix's approach.

    1. Score all flow records by anomaly heuristics
    2. Sort by score (descending)
    3. Return top-k as "retrieved contexts"
    """
    scored_flows = []

    for entry in ground_truth:
        score = calculate_anomaly_score(
            entry['strategy_b_features'],
            entry['attack_class']
        )

        # Create context text (same format as Vector RAG for fair comparison)
        context = (
            f"Attack detected: {entry['attack_class']}. "
            f"Anomaly score: {score:.1f}. "
            f"Top features: "
            f"Rolling_SYN_Sum={entry['strategy_b_features'].get('Rolling_SYN_Sum', 0):.0f}, "
            f"Rolling_ACK_Sum={entry['strategy_b_features'].get('Rolling_ACK_Sum', 0):.0f}, "
            f"Rolling_UDP_Sum={entry['strategy_b_features'].get('Rolling_UDP_Sum', 0):.0f}, "
            f"src2dst_packets={entry['strategy_b_features'].get('src2dst_packets', 0)}, "
            f"Unique_Ports={entry['strategy_b_features'].get('Unique_Ports', 0)}."
        )

        scored_flows.append({
            'score': score,
            'context': context,
            'attack_class': entry['attack_class']
        })

    # Sort by anomaly score (highest = most suspicious)
    scored_flows.sort(key=lambda x: x['score'], reverse=True)

    # Return top-k contexts
    return [f['context'] for f in scored_flows[:top_k]]


# ═══════════════════════════════════════════════════════════════════════════
# 4. RAG Pipeline (same as other experiments)
# ═══════════════════════════════════════════════════════════════════════════

from run_experiment_2 import (
    ETSI_PROVISIONS,
    provision_chunks,
    llm_registry,
    build_prompt,
    run_ragas_eval
)

def run_heuristic_rag(question: str, llm_fn, top_k: int = 5) -> Dict[str, Any]:
    """Run RAG with heuristic retrieval instead of vector/graph retrieval."""
    # Retrieve using heuristic scoring
    flow_contexts = retrieve_by_heuristic(question, ground_truth, top_k=3)

    # Add ETSI provisions (same as other approaches)
    contexts = flow_contexts + provision_chunks[:2]

    # Build prompt (same format)
    prompt = build_prompt(question, contexts)

    # Generate answer
    answer = llm_fn(prompt)

    return {
        'question': question,
        'answer': answer,
        'contexts': contexts,
        'prompt': prompt
    }


# ═══════════════════════════════════════════════════════════════════════════
# 5. Run Experiment
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("Experiment 5: Rule-Based Heuristic Baseline")
print("="*80 + "\n")

results_records = []

for llm_name, llm_fn in llm_registry.items():
    print(f"\n{'='*60}")
    print(f"Running: Heuristic + {llm_name}")
    print(f"{'='*60}")

    answers_data = []
    gt_answers = []

    from tqdm import tqdm
    for entry in tqdm(ground_truth, desc=f'Heuristic-{llm_name}'):
        try:
            result = run_heuristic_rag(entry['question'], llm_fn, top_k=5)
            answers_data.append(result)
            gt_answers.append(entry['ground_truth'])
        except Exception as e:
            print(f"  Error on {entry['id']}: {e}")
            answers_data.append({
                'question': entry['question'],
                'answer': 'ERROR',
                'contexts': []
            })
            gt_answers.append(entry['ground_truth'])

    # Evaluate with RAGAS
    print("\n  Evaluating with RAGAS...")
    ragas_df = run_ragas_eval(answers_data, gt_answers)
    ragas_df['technique'] = 'Heuristic (Rule-Based)'
    ragas_df['llm'] = llm_name
    results_records.append(ragas_df)

    print("\n  Mean scores:")
    print(ragas_df[['faithfulness', 'context_precision', 'context_recall',
                    'answer_correctness', 'answer_relevancy']].mean())

# Save results
all_results = pd.concat(results_records, ignore_index=True)
os.makedirs(f'{BASE_PATH}/results', exist_ok=True)
all_results.to_csv(f'{BASE_PATH}/results/heuristic_baseline_results.csv', index=False)

print("\n" + "="*80)
print("Heuristic Baseline Complete!")
print("="*80)
print(f"\n✓ Results saved to: results/heuristic_baseline_results.csv")
print(f"  Shape: {all_results.shape}")
print("\n  Summary:")
print(all_results.groupby('llm')[['faithfulness', 'context_precision',
                                   'context_recall', 'answer_correctness']].mean())
