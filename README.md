# SACA: Security Audit Compliance Agent

Official code repository for the paper:

**"Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"**

*Obrina Briliyant, Amir Javed, Yulia Cherdantseva*  
School of Computer Science and Informatics, Cardiff University

📄 **Published in:** MDPI Journal of Cybersecurity and Privacy [pending]  
🔗 **Paper:** [Link TBD]  
📊 **Dataset:** [CIC-IoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

---

## 🎯 Abstract

We present the first systematic comparison of retrieval paradigms for generating faithful compliance explanations in IoT network security auditing. Evaluating rule-based heuristics, dense vector RAG, and knowledge graph traversal across 30 expert-validated scenarios from CIC-IoT2023 against ETSI EN 303 645, we identify a critical **accuracy-faithfulness gap**: while intrusion detection achieves F1 > 0.97, over 40% of LLM-generated compliance statements remain unsupported by retrieved evidence. Graph RAG demonstrates the most consistent performance (CV=10.1% across LLMs) with near-perfect context precision (0.996), though differences are not statistically significant (p=0.35).

---

## 🔑 Key Findings

- **Accuracy ≠ Faithfulness:** High detection F1 (0.97+) coexists with low explanation quality (faithfulness 0.50-0.57)
- **40%+ Unsupported Claims:** Nearly half of LLM statements lack grounding in retrieved evidence
- **Graph RAG Consistency:** Lowest coefficient of variation (10.1%) across LLMs and attack types
- **Near-Perfect Precision:** Graph RAG achieves 0.996 context precision
- **Statistical Reality:** Differences not significant at conventional thresholds (ANOVA p=0.35, Cohen's d<0.2)

| Method | Faithfulness | Precision | Recall | CV (LLMs) |
|--------|-------------|-----------|--------|-----------|
| Rule-based | 0.524 | 0.814 | 0.124 | 11.2% |
| Vector RAG | 0.509 | 0.856 | 0.224 | 19.8% |
| **Graph RAG** | **0.570** | **0.996** | 0.189 | **10.1%** ⭐ |

---

## 📂 Repository Structure

```
saca-iot-compliance/
├── README.md                           # This file
├── LICENSE                             # MIT License
├── .gitignore                          # Git ignore rules
├── requirements.txt                    # Python dependencies
│
├── data/                               # Ground truth and dataset info
│   ├── README.md                       # Dataset download instructions
│   └── compliance_ground_truth.json    # 30 expert-validated scenarios
│
├── experiments/                        # Main experiment scripts
│   ├── experiment_2_vector_rag.py      # Vector RAG with ChromaDB
│   ├── experiment_3_lightrag.py        # Graph RAG with Neo4j
│   └── experiment_5_heuristic_baseline.py  # Rule-based scoring
│
├── src/                                # Reusable modules
│   ├── __init__.py
│   ├── heuristic_scorer.py             # Anomaly scoring functions
│   └── ragas_evaluator.py              # RAGAS evaluation utilities
│
├── saca_prototype/                     # SACA web application
│   ├── docker-compose.yml              # Neo4j + app containers
│   └── src/
│       ├── pcap_processor.py           # PCAP to knowledge graph
│       └── enhanced_knowledge_graph.py # Graph construction
│
├── visualization/                      # Figure generation scripts
│   ├── figure_2_llm_heatmap.py         # LLM faithfulness heatmap
│   └── figure_3_precision_recall.py    # Precision-recall scatter
│
├── results/                            # Experimental results
│   ├── heuristic_baseline_results_filtered.csv
│   ├── vector_rag_compliance_results_filtered.csv
│   └── lightrag_compliance_results_FINAL.csv
│
└── docs/                               # Documentation
    ├── METHODOLOGY.md                  # Detailed methods
    ├── ETSI_EN_303_645_MAPPING.md      # Attack-to-provision mapping
    └── REPRODUCTION_GUIDE.md           # Step-by-step reproduction
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Neo4j 5.0+ (for Graph RAG)
- NVIDIA GPU with CUDA at least 12GB VRAM for 8B model (for local LLMs)
- API keys (optional, for fallback):
  - OpenRouter (DeepSeek-R1, Qwen-2.5, Llama-3.2)
  - OpenAI (GPT-4o-mini for RAGAS LLM-as-judge)

### Installation

```bash
# Clone repository
git clone https://github.com/abyasham/towards_responsible_AI_IoT_security_compliance_using_graph_ragas.git
cd towards_responsible_AI_IoT_security_compliance_using_graph_ragas

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Download Dataset

The CIC-IoT2023 dataset is not included due to size. Download from:
https://www.unb.ca/cic/datasets/iotdataset-2023.html

Place `df_class_8_test.csv` in `dataset/` directory.

### Run Experiments

```bash
# Experiment 5: Rule-based Heuristic
python experiments/experiment_5_heuristic_baseline.py

# Experiment 2: Vector RAG
python experiments/experiment_2_vector_rag.py

# Experiment 3: Graph RAG (requires Neo4j running)
docker-compose -f saca_prototype/docker-compose.yml up -d
python experiments/experiment_3_lightrag.py
```

### Generate Figures

```bash
cd visualization
python figure_2_llm_heatmap.py
python figure_3_precision_recall.py
```

---

## 📊 Reproducing Paper Results

See [`docs/REPRODUCTION_GUIDE.md`](docs/REPRODUCTION_GUIDE.md) for detailed step-by-step instructions to reproduce all experiments, figures, and statistical analyses from the paper.

Expected runtime:
- Experiment 5 (Heuristic): ~2 hours (120 evaluations)
- Experiment 2 (Vector RAG): ~3 hours (120 evaluations)
- Experiment 3 (Graph RAG): ~2.5 hours (120 evaluations)

---

## 🗂️ Dataset

**CIC-IoT2023:**
- **Source:** https://www.unb.ca/cic/datasets/iotdataset-2023.html
- **Test set:** 25,557 flows across 8 classes
- **Features:** 97 flow-level metrics from CICFlowMeter
- **Classes:** Benign, Backdoor, DoS, DDoS, Spoofing, Recon, WebBased, BruteForce

**Ground Truth (Included):**
- **File:** `data/compliance_ground_truth.json`
- **Scenarios:** 30 expert-validated compliance queries
- **Inter-annotator agreement:** Cohen's κ=0.62
- **Mapping:** ETSI EN 303 645 provisions to attack classes

---

## 📖 Citation

If you use this code or dataset in your research, please cite:

```bibtex
@article{briliyant2026saca,
  title={Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS},
  author={Briliyant, Obrina and Javed, Amir and Cherdantseva, Yulia},
  journal={Journal of Cybersecurity and Privacy},
  volume={TBD},
  number={TBD},
  pages={TBD},
  year={2026},
  publisher={MDPI},
  doi={TBD}
}
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📬 Contact

**Obrina Briliyant**  
School of Computer Science and Informatics  
Cardiff University  
Email: BriliyantO@cardiff.ac.uk

For questions about the paper or code, please open an issue on GitHub or contact the authors directly.

---

## 🙏 Acknowledgments

- **CIC-IoT2023 Dataset:** Canadian Institute for Cybersecurity, University of New Brunswick
- **LightRAG Framework:** HKUST-KnowComp
- **RAGAS Metrics:** Explodinggradients
- **Funding:** [Add funding sources if applicable]

---

## 📝 Notes for Reviewers

This repository contains all code, data, and documentation to reproduce the results presented in our manuscript. We provide:

1. ✅ Complete experimental pipeline (3 retrieval methods)
2. ✅ Ground truth annotations (30 scenarios, validated)
3. ✅ Raw experimental results (filtered CSVs)
4. ✅ Visualization code (publication-ready figures)
5. ✅ SACA prototype (web interface with Neo4j)
6. ✅ Detailed methodology documentation

**Data Availability:** All data and code are publicly available in this repository. The CIC-IoT2023 dataset is publicly available at the URL provided above.
