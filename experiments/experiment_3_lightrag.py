#!/usr/bin/env python3
"""
Experiment 3: Graph RAG with Knowledge Graph Traversal

Paper: "Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"
Authors: Obrina Briliyant, Amir Javed, Yulia Cherdantseva
Affiliation: Cardiff University

Description:
    Implements LightRAG-based knowledge graph retrieval using Neo4j.
    Constructs Flow→AttackClass→Provision ontology for compliance reasoning.

Usage:
    python experiment_3_lightrag.py

Requirements:
    - compliance_ground_truth.json in data/
    - Neo4j running on bolt://localhost:7687
    - Environment variables: OPENROUTER_API_KEY, GOOGLE_API_KEY
"""
import os
import sys
import warnings
warnings.filterwarnings('ignore')
os.environ['GRPC_VERBOSITY'] = 'ERROR'
os.environ['GLOG_minloglevel'] = '2'

import json
import pandas as pd
import numpy as np
from typing import List, Dict, Any
from dotenv import load_dotenv
from tqdm import tqdm
import time

# Load environment variables
load_dotenv()
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')

if not OPENROUTER_API_KEY:
    print("❌ OPENROUTER_API_KEY not found in .env file")
    exit(1)

print("✓ API keys loaded")

# Set base path
BASE_PATH = '/home/abyasa/Documents/mdpi_experiment'

# ═══════════════════════════════════════════════════════════════════════════
# Import from Experiment 2
# ═══════════════════════════════════════════════════════════════════════════

from run_experiment_2 import (
    ground_truth,
    ETSI_PROVISIONS,
    provision_chunks,
    serialise_strategy_b,
    build_prompt,
    run_ragas_eval
)

print(f"✓ Loaded {len(ground_truth)} ground-truth scenarios")

# ═══════════════════════════════════════════════════════════════════════════
# Neo4j Knowledge Graph Setup
# ═══════════════════════════════════════════════════════════════════════════

from neo4j import GraphDatabase

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "password"

print(f"Connecting to Neo4j at {NEO4J_URI}...")
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Test connection
try:
    with driver.session() as session:
        result = session.run("RETURN 1 as test")
        assert result.single()["test"] == 1
    print("✓ Neo4j connected")
except Exception as e:
    print(f"❌ Neo4j connection failed: {e}")
    print("   Ensure Neo4j is running: cd saca-lightrag && docker compose up -d")
    exit(1)

# ═══════════════════════════════════════════════════════════════════════════
# Build Knowledge Graph
# ═══════════════════════════════════════════════════════════════════════════

def clear_graph():
    """Clear all nodes and relationships"""
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

def build_knowledge_graph():
    """Build knowledge graph from ground truth scenarios"""
    print("\nBuilding Knowledge Graph...")
    clear_graph()

    with driver.session() as session:
        # Create ETSI Provision nodes
        for prov_id, prov_text in ETSI_PROVISIONS.items():
            session.run("""
                MERGE (p:Provision {id: $id})
                SET p.text = $text, p.provision_id = $prov_id
            """, id=f"ETSI_{prov_id}", text=prov_text, prov_id=prov_id)

        # Create Flow and Attack nodes from ground truth
        for entry in ground_truth:
            flow_text = serialise_strategy_b(entry['strategy_b_features'], entry['attack_class'])

            # Create Flow node
            session.run("""
                MERGE (f:Flow {id: $id})
                SET f.text = $text,
                    f.attack_class = $attack_class,
                    f.question = $question,
                    f.ground_truth = $ground_truth
            """, id=entry['id'], text=flow_text,
                 attack_class=entry['attack_class'],
                 question=entry['question'],
                 ground_truth=entry['ground_truth'])

            # Create Attack node
            session.run("""
                MERGE (a:AttackClass {name: $name})
            """, name=entry['attack_class'])

            # Create relationships
            session.run("""
                MATCH (f:Flow {id: $flow_id})
                MATCH (a:AttackClass {name: $attack_class})
                MERGE (f)-[:IS_TYPE]->(a)
            """, flow_id=entry['id'], attack_class=entry['attack_class'])

            # Link to ETSI provision
            prov_id = f"ETSI_{entry['etsi_provision']}"
            session.run("""
                MATCH (f:Flow {id: $flow_id})
                MATCH (p:Provision {id: $prov_id})
                MERGE (f)-[:VIOLATES]->(p)
            """, flow_id=entry['id'], prov_id=prov_id)

    # Verify graph
    with driver.session() as session:
        flow_count = session.run("MATCH (f:Flow) RETURN count(f) as count").single()["count"]
        prov_count = session.run("MATCH (p:Provision) RETURN count(p) as count").single()["count"]
        attack_count = session.run("MATCH (a:AttackClass) RETURN count(a) as count").single()["count"]

    print(f"✓ Knowledge Graph built:")
    print(f"  - {flow_count} Flow nodes")
    print(f"  - {prov_count} Provision nodes")
    print(f"  - {attack_count} Attack class nodes")

build_knowledge_graph()

# ═══════════════════════════════════════════════════════════════════════════
# LightRAG Retrieval (Hybrid Mode)
# ═══════════════════════════════════════════════════════════════════════════

def retrieve_lightrag_hybrid(question: str, top_k: int = 5) -> List[str]:
    """
    LightRAG Hybrid retrieval: Local + Global graph traversal
    """
    with driver.session() as session:
        # Extract attack keywords from question
        attack_keywords = {
            'brute': 'BruteForce', 'password': 'BruteForce', 'credential': 'BruteForce',
            'ddos': 'DDoS', 'dos': 'DoS', 'denial': 'DoS',
            'recon': 'Recon', 'scan': 'Recon', 'port': 'Recon',
            'spoof': 'Spoofing', 'arp': 'Spoofing', 'dns': 'Spoofing', 'mitm': 'Spoofing',
            'sql': 'WebBased', 'xss': 'WebBased', 'injection': 'WebBased', 'exploit': 'WebBased',
            'backdoor': 'Backdoor', 'mirai': 'Backdoor', 'malware': 'Backdoor',
        }

        # Match attack type from question
        question_lower = question.lower()
        matched_attack = None
        for keyword, attack in attack_keywords.items():
            if keyword in question_lower:
                matched_attack = attack
                break

        contexts = []

        # Local: Get flows of matching attack type
        if matched_attack:
            result = session.run("""
                MATCH (f:Flow)-[:IS_TYPE]->(a:AttackClass {name: $attack})
                RETURN f.text as text
                LIMIT $limit
            """, attack=matched_attack, limit=top_k // 2)
            contexts.extend([record["text"] for record in result])

        # Global: Get related provisions
        if matched_attack:
            result = session.run("""
                MATCH (a:AttackClass {name: $attack})<-[:IS_TYPE]-(f:Flow)-[:VIOLATES]->(p:Provision)
                RETURN DISTINCT p.text as text
                LIMIT 2
            """, attack=matched_attack)
            contexts.extend([record["text"] for record in result])

        # Fallback: If no match, get random flows + provisions
        if len(contexts) == 0:
            result = session.run("""
                MATCH (f:Flow)
                RETURN f.text as text
                ORDER BY rand()
                LIMIT $limit
            """, limit=top_k // 2)
            contexts.extend([record["text"] for record in result])
            contexts.extend(provision_chunks[:2])

        return contexts[:top_k]

# ═══════════════════════════════════════════════════════════════════════════
# LLM Setup (CORRECTED - Using actual installed models)
# ═══════════════════════════════════════════════════════════════════════════

import requests

def call_ollama(model_name: str, prompt: str, timeout: int = 180) -> str:
    """Call Ollama API with proper timeout"""
    try:
        resp = requests.post(
            'http://localhost:11434/api/generate',
            json={
                'model': model_name,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': 0.1,
                    'num_predict': 300,
                }
            },
            timeout=timeout
        )
        resp.raise_for_status()
        return resp.json()['response'].strip()
    except Exception as e:
        return f"ERROR: {str(e)}"

# LLM wrappers using ACTUAL model names from ollama list
def llm_deepseek_local(prompt: str) -> str:
    return call_ollama('deepseek-r1:8b', prompt, timeout=180)

def llm_qwen_local(prompt: str) -> str:
    return call_ollama('qwen2.5:7b', prompt, timeout=180)

def llm_llama_local(prompt: str) -> str:
    return call_ollama('llama3.2:latest', prompt, timeout=180)

def llm_nu11security(prompt: str) -> str:
    """nu11secur1tyAI4 - Cybersecurity specialist model (15GB, may be slow)"""
    return call_ollama('f0rc3ps/nu11secur1tyAI4:latest', prompt, timeout=300)

def llm_gpt4o_mini(prompt: str) -> str:
    """GPT-4o-mini via OpenRouter API"""
    try:
        resp = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {OPENROUTER_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'model': 'openai/gpt-4o-mini',
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0.1,
                'max_tokens': 300
            },
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"ERROR: {str(e)}"

# LLM Registry with CORRECT model names
llm_registry = {
    'DeepSeek-R1-8B (Local)': llm_deepseek_local,
    'Qwen-2.5-7B (Local)': llm_qwen_local,
    'nu11secur1tyAI4 (Cyber-Specialist)': llm_nu11security,
    'Llama-3.2-3B (Local)': llm_llama_local,
    'GPT-4o-mini (API)': llm_gpt4o_mini,
}

print(f"✓ LLM registry ready: {list(llm_registry.keys())}")

# ═══════════════════════════════════════════════════════════════════════════
# RAG Pipeline
# ═══════════════════════════════════════════════════════════════════════════

def run_lightrag(question: str, llm_fn, top_k: int = 5) -> Dict[str, Any]:
    """Run RAG with LightRAG hybrid retrieval"""
    contexts = retrieve_lightrag_hybrid(question, top_k)
    prompt = build_prompt(question, contexts)
    answer = llm_fn(prompt)

    return {
        'question': question,
        'answer': answer,
        'contexts': contexts,
        'prompt': prompt
    }

print('✓ LightRAG pipeline ready')

# ═══════════════════════════════════════════════════════════════════════════
# Run Experiment
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*80)
    print("Experiment 3: LightRAG Knowledge Graph (CLEAN RUN)")
    print("5 LLMs × 30 scenarios = 150 evaluations")
    print("="*80 + "\n")

    results_records = []

    for llm_name, llm_fn in llm_registry.items():
        print(f"\n{'='*80}")
        print(f"Testing: {llm_name}")
        print(f"{'='*80}")

        answers_data = []
        gt_answers = []

        for i, entry in enumerate(tqdm(ground_truth, desc=f"{llm_name}")):
            try:
                result = run_lightrag(entry['question'], llm_fn, top_k=5)
                answers_data.append(result)
                gt_answers.append(entry['ground_truth'])
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                print(f"\n  ❌ Error on scenario {i+1}: {str(e)}")
                answers_data.append({
                    'question': entry['question'],
                    'answer': f'ERROR: {str(e)}',
                    'contexts': []
                })
                gt_answers.append(entry['ground_truth'])

        # Evaluate with RAGAS
        print(f"\n  Evaluating with RAGAS...")
        try:
            ragas_df = run_ragas_eval(answers_data, gt_answers)
            ragas_df['technique'] = 'LightRAG (Knowledge Graph)'
            ragas_df['llm'] = llm_name
            results_records.append(ragas_df)

            print(f"\n  Mean scores for {llm_name}:")
            summary = ragas_df[['faithfulness', 'context_precision', 'context_recall',
                               'answer_correctness', 'answer_relevancy']].mean()
            print(summary)

        except Exception as e:
            print(f"\n  ❌ RAGAS evaluation failed: {str(e)}")
            continue

    # Save final results
    if results_records:
        all_results = pd.concat(results_records, ignore_index=True)
        os.makedirs(f'{BASE_PATH}/results', exist_ok=True)
        output_path = f'{BASE_PATH}/results/lightrag_compliance_results_clean.csv'
        all_results.to_csv(output_path, index=False)

        print("\n" + "="*80)
        print("EXPERIMENT 3 COMPLETE")
        print("="*80)
        print(f"\nTotal evaluations: {len(all_results)}")
        print(f"Expected: 150 (5 LLMs × 30 scenarios)")
        print(f"Success rate: {len(all_results)/150*100:.1f}%")
        print(f"\nResults saved to: {output_path}")

        # Summary statistics
        print("\nSummary by LLM:")
        print("-" * 80)
        summary = all_results.groupby('llm')[['faithfulness', 'context_precision',
                                               'context_recall']].agg(['mean', 'count'])
        print(summary)

        # Check for errors
        error_count = all_results['response'].str.contains('ERROR', case=False, na=False).sum()
        print(f"\nError responses: {error_count} / {len(all_results)} ({error_count/len(all_results)*100:.1f}%)")

    else:
        print("\n❌ No results collected - all LLMs failed")

    # Close Neo4j connection
    driver.close()
    print("\n✓ Neo4j connection closed")
