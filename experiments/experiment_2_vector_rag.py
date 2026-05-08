#!/usr/bin/env python3
"""
Experiment 2: Vector RAG with Dense Embeddings

Paper: "Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"
Authors: Obrina Briliyant, Amir Javed, Yulia Cherdantseva
Affiliation: Cardiff University

Description:
    Implements ChromaDB-based vector RAG using nomic-embed-text embeddings.
    Retrieves flow features via cosine similarity for compliance analysis.

Usage:
    python experiment_2_vector_rag.py

Requirements:
    - compliance_ground_truth.json in data/
    - CIC-IoT2023 test dataset (df_class_8_test.csv)
    - Environment variables: OPENAI_API_KEY, OPENROUTER_API_KEY, GOOGLE_API_KEY
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
from typing import List, Dict, Any, Callable
from dotenv import load_dotenv
from tqdm import tqdm
import time

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')

if not OPENAI_API_KEY:
    print("⚠️  OPENAI_API_KEY not found in .env file")
    print("   Get one from: https://platform.openai.com/api-keys")
    exit(1)

print("✓ API keys loaded")

# Set base path
BASE_PATH = '/home/abyasa/Documents/mdpi_experiment'

# ═══════════════════════════════════════════════════════════════════════════
# Cell 2: Load Ground Truth
# ═══════════════════════════════════════════════════════════════════════════

gt_path = os.path.join(BASE_PATH, 'compliance_ground_truth.json')
with open(gt_path, 'r') as f:
    ground_truth = json.load(f)

print(f"✓ Loaded {len(ground_truth)} ground-truth scenarios")

# ═══════════════════════════════════════════════════════════════════════════
# Cell 3: ETSI EN 303 645 Provision Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════

ETSI_PROVISIONS = {
    '5.1': "Provision 5.1 — No universal default passwords. IoT devices shall not have default passwords that are the same across all devices of a product class. The device shall require the user to define a unique password before use or shall implement a mechanism that ensures each device has a unique password. Brute-force attacks against authentication endpoints indicate devices may be using weak or default credentials.",
    '5.3': "Provision 5.3 — Keep software updated. IoT device software shall be updateable. The manufacturer shall publish information on how vulnerabilities in the device can be reported, and shall act on such reports in a timely manner. Exploitation of known vulnerabilities (e.g., SQL injection, XSS, command injection) in web interfaces indicates failure to keep software updated.",
    '5.5': "Provision 5.5 — Communicate securely. Security-sensitive data, including any remote management and control, shall be encrypted in transit. Where cryptography is used, the device shall use secure, trusted mechanisms. ARP spoofing, DNS spoofing, and unencrypted control traffic indicate violation of secure communication requirements.",
    '5.6': "Provision 5.6 — Minimise exposed attack surfaces. All unnecessary network ports and services shall be disabled. The device shall minimise the externally exposed attack surface. Reconnaissance traffic such as port scanning, OS fingerprinting, and ping sweeps indicate excessive exposed attack surfaces.",
    '5.7': "Provision 5.7 — Ensure software integrity and DoS resilience. The device shall verify the integrity of its software and maintain secure operation. IoT devices shall remain operational and resilient under denial-of-service conditions, or shall fail safely. Malware compromise (backdoors, Mirai), DDoS floods, and DoS attacks indicate violation of software integrity and resilience requirements.",
}

def chunk_provisions(provisions: Dict[str, str]) -> List[str]:
    chunks = []
    for provision_id, text in provisions.items():
        chunks.append(f"[ETSI {provision_id}] {text}")
    return chunks

provision_chunks = chunk_provisions(ETSI_PROVISIONS)
print(f"✓ Created {len(provision_chunks)} provision chunks")

# ═══════════════════════════════════════════════════════════════════════════
# Cell 4: Serialise Flow Records (Strategy B)
# ═══════════════════════════════════════════════════════════════════════════

def serialise_strategy_b(features: Dict[str, Any], attack_class: str) -> str:
    """Full IG-aware serialisation of flow record features."""
    text = (
        f"Attack detected: {attack_class}. "
        f"Top features by importance: "
        f"Rolling_SYN_Sum={features.get('Rolling_SYN_Sum', 0):.0f}, "
        f"Rolling_ACK_Sum={features.get('Rolling_ACK_Sum', 0):.0f}, "
        f"Rolling_UDP_Sum={features.get('Rolling_UDP_Sum', 0):.0f}, "
        f"src2dst_packets={features.get('src2dst_packets', 0)}, "
        f"src2dst_bytes={features.get('src2dst_bytes', 0)}, "
        f"bidirectional_mean_ps={features.get('bidirectional_mean_ps', 0):.1f}, "
        f"packet_size_variation={features.get('packet_size_variation', 0):.2f}, "
        f"Unique_Ports={features.get('Unique_Ports', 0)}. "
        f"Flow duration and temporal window statistics are embedded in the rolling sums."
    )
    return text

serialised_documents = []
for entry in ground_truth:
    doc_text = serialise_strategy_b(entry['strategy_b_features'], entry['attack_class'])
    serialised_documents.append({
        'id': entry['id'],
        'text': doc_text,
        'attack_class': entry['attack_class'],
        'provision': entry['etsi_provision']
    })

print(f"✓ Serialised {len(serialised_documents)} flow records")

# ═══════════════════════════════════════════════════════════════════════════
# Cell 5: Initialize ChromaDB with Embeddings (using Ollama local model)
# ═══════════════════════════════════════════════════════════════════════════

import chromadb
from chromadb.config import Settings
import requests

print('Loading embedding model: nomic-embed-text (Ollama) ...')

def embed_minilm(texts: List[str]) -> np.ndarray:
    """Use Ollama embedding API (local, no API key needed)"""
    embeddings = []
    for text in texts:
        resp = requests.post(
            'http://localhost:11434/api/embeddings',
            json={
                'model': 'nomic-embed-text',
                'prompt': text
            },
            timeout=30
        )
        resp.raise_for_status()
        embeddings.append(resp.json()['embedding'])
    return np.array(embeddings)

print('✓ Embedding model ready (using Ollama, 100% local)')

def build_chroma_collection(documents, embed_fn, collection_name):
    client = chromadb.Client(Settings(anonymized_telemetry=False))
    try:
        client.delete_collection(collection_name)
    except Exception:
        pass
    collection = client.create_collection(name=collection_name)
    texts     = [d['text'] for d in documents] + provision_chunks
    ids       = [d['id']   for d in documents] + [f'prov_{i}' for i in range(len(provision_chunks))]
    metadatas = ([{'type': 'flow', 'attack': d['attack_class'], 'provision': d['provision']} for d in documents]
               + [{'type': 'provision'} for _ in provision_chunks])
    all_embeddings = embed_fn(texts)
    collection.add(
        embeddings=all_embeddings.tolist(),
        documents=texts,
        ids=ids,
        metadatas=metadatas,
    )
    print(f'  {collection_name}: {len(texts)} docs indexed')
    return collection

print('Building ChromaDB collection...')
collection_minilm = build_chroma_collection(serialised_documents, embed_minilm, 'vector_rag_minilm')
print('✓ Collection ready')

# ═══════════════════════════════════════════════════════════════════════════
# Cell 6: LLM Setup (Ollama local models)
# ═══════════════════════════════════════════════════════════════════════════

import requests

def call_ollama(model_name: str, prompt: str) -> str:
    """Call Ollama API running on localhost"""
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
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()['response'].strip()
    except Exception as e:
        print(f"  Error calling Ollama {model_name}: {e}")
        return f"ERROR: {str(e)}"

def llm_deepseek_local(prompt: str) -> str:
    return call_ollama('deepseek-r1:8b', prompt)

def llm_qwen_local(prompt: str) -> str:
    return call_ollama('qwen2.5:7b', prompt)

def llm_llama_local(prompt: str) -> str:
    return call_ollama('llama3.2:latest', prompt)

def llm_nu11security(prompt: str) -> str:
    """nu11secur1tyAI4 - Cybersecurity specialist model"""
    return call_ollama('f0rc3ps/nu11secur1tyAI4', prompt)

# Optional: Keep GPT-4o-mini via OpenRouter for comparison
def llm_gpt4o_mini(prompt: str) -> str:
    if not OPENROUTER_API_KEY:
        return "SKIPPED (no API key)"
    resp = requests.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {OPENROUTER_API_KEY}', 'Content-Type': 'application/json'},
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

llm_registry = {
    'DeepSeek-R1-8B (Local)': llm_deepseek_local,
    'Qwen-2.5-7B (Local)': llm_qwen_local,
    'nu11secur1tyAI4 (Cyber-Specialist)': llm_nu11security,
    'Llama-3.2-3B (Local)': llm_llama_local,
}

if OPENROUTER_API_KEY:
    llm_registry['GPT-4o-mini (API)'] = llm_gpt4o_mini

print(f"✓ LLM registry ready: {list(llm_registry.keys())}")

# ═══════════════════════════════════════════════════════════════════════════
# Cell 7: RAG Pipeline
# ═══════════════════════════════════════════════════════════════════════════

_collection_embed_map = {
    'vector_rag_minilm': embed_minilm,
}

def retrieve_context(collection, query: str, top_k: int = 5) -> List[str]:
    """Retrieve top-k documents from ChromaDB."""
    embed_fn = _collection_embed_map.get(collection.name, embed_minilm)
    q_emb = embed_fn([query])[0].tolist()
    results = collection.query(query_embeddings=[q_emb], n_results=top_k)
    return results['documents'][0]

def build_prompt(question: str, contexts: List[str]) -> str:
    """Build compliance analysis prompt."""
    context_block = "\n\n".join([f"[{i+1}] {c}" for i, c in enumerate(contexts)])
    prompt = (
        f"You are a network-security compliance analyst. Answer the question using ONLY the retrieved evidence below.\n\n"
        f"Retrieved Evidence:\n{context_block}\n\n"
        f"Question: {question}\n\n"
        f"Provide a YES/NO verdict with a 1-sentence justification citing specific features or provisions."
    )
    return prompt

def run_rag(collection, question: str, llm_fn: Callable, top_k: int = 5) -> Dict[str, Any]:
    contexts = retrieve_context(collection, question, top_k)
    prompt = build_prompt(question, contexts)
    answer = llm_fn(prompt)
    return {
        'question': question,
        'answer': answer,
        'contexts': contexts,
        'prompt': prompt
    }

print('✓ RAG pipeline ready')

# ═══════════════════════════════════════════════════════════════════════════
# Cell 8: RAGAS Evaluation Harness
# ═══════════════════════════════════════════════════════════════════════════

from datasets import Dataset
from ragas import evaluate
from ragas.metrics import Faithfulness, ContextPrecision, ContextRecall, AnswerCorrectness, AnswerRelevancy
from ragas.llms import LangchainLLMWrapper
from ragas.embeddings import LangchainEmbeddingsWrapper
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

_judge_llm = LangchainLLMWrapper(
    ChatOpenAI(
        model='gpt-4o-mini',
        api_key=OPENAI_API_KEY,
        temperature=0,
    )
)
_judge_emb = LangchainEmbeddingsWrapper(
    OpenAIEmbeddings(
        model='text-embedding-3-small',
        api_key=OPENAI_API_KEY,
    )
)

_metrics = [
    Faithfulness(llm=_judge_llm),
    ContextPrecision(llm=_judge_llm),
    ContextRecall(llm=_judge_llm),
    AnswerCorrectness(llm=_judge_llm, embeddings=_judge_emb),
    AnswerRelevancy(llm=_judge_llm, embeddings=_judge_emb),
]
print('✓ RAGAS judge: GPT-4o-mini')

def run_ragas_eval(answers_data: List[Dict], ground_truths: List[str]) -> pd.DataFrame:
    """Evaluate with RAGAS 0.2.x using Gemini as judge."""
    hf_ds = Dataset.from_dict({
        'question':     [d['question'] for d in answers_data],
        'answer':       [d['answer']   for d in answers_data],
        'contexts':     [d['contexts'] for d in answers_data],
        'ground_truth': ground_truths,
    })
    result = evaluate(
        dataset=hf_ds,
        metrics=_metrics,
        raise_exceptions=False,
    )
    df = result.to_pandas()
    df.columns = [c.lower().replace(' ', '_') for c in df.columns]
    return df

print('✓ RAGAS evaluation harness ready')

# ═══════════════════════════════════════════════════════════════════════════
# Cell 9: Run Experiment
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*80)
    print("Starting Experiment 2: Vector RAG Baseline")
    print("="*80 + "\n")

    results_records = []
    embedding_variants = [
        ('HF-MiniLM-L6-v2', embed_minilm, 'vector_rag_minilm'),
    ]

    _collection_cache = {
        'vector_rag_minilm': collection_minilm,
    }

    for embed_name, embed_fn, coll_name in embedding_variants:
        collection = _collection_cache.get(coll_name)

        for llm_name, llm_fn in llm_registry.items():
            print(f"\n{'='*60}")
            print(f"Running: {embed_name} + {llm_name}")
            print(f"{'='*60}")
            answers_data = []
            gt_answers = []

            for entry in tqdm(ground_truth, desc=f'{embed_name}-{llm_name}'):
                try:
                    result = run_rag(collection, entry['question'], llm_fn, top_k=5)
                    answers_data.append(result)
                    gt_answers.append(entry['ground_truth'])
                    time.sleep(0.5)  # rate limiting
                except Exception as e:
                    print(f"  Error on {entry['id']}: {e}")
                    answers_data.append({'question': entry['question'], 'answer': 'ERROR', 'contexts': []})
                    gt_answers.append(entry['ground_truth'])

            # Evaluate with RAGAS
            print("\n  Evaluating with RAGAS...")
            ragas_df = run_ragas_eval(answers_data, gt_answers)
            ragas_df['embedding'] = embed_name
            ragas_df['llm'] = llm_name
            ragas_df['technique'] = 'Vector RAG (Dense)'
            results_records.append(ragas_df)

            print("\n  Mean scores:")
            print(ragas_df[['faithfulness', 'context_precision', 'context_recall', 'answer_correctness', 'answer_relevancy']].mean())

    # ═══════════════════════════════════════════════════════════════════════════
    # Cell 10: Save Results
    # ═══════════════════════════════════════════════════════════════════════════

    all_results = pd.concat(results_records, ignore_index=True)

    out_dir = os.path.join(BASE_PATH, 'results')
    os.makedirs(out_dir, exist_ok=True)

    csv_path = os.path.join(out_dir, 'vector_rag_compliance_results.csv')
    pkl_path = os.path.join(out_dir, 'vector_rag_compliance_results.pkl')
    all_results.to_csv(csv_path, index=False)
    all_results.to_pickle(pkl_path)

    print("\n" + "="*80)
    print("Experiment Complete!")
    print("="*80)
    print(f"\n✓ Results saved to: {csv_path}")
    print(f"  Shape: {all_results.shape}")
    print("\n  Summary by LLM:")
    print(all_results.groupby(['llm'])[['faithfulness', 'context_precision', 'context_recall', 'answer_correctness']].mean())
