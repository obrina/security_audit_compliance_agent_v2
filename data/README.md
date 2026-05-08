# Data Directory

## CIC-IoT2023 Dataset

The full CIC-IoT2023 dataset used in this research is **not included** in this repository due to its size (1.4GB).

### Download Instructions

The dataset is publicly available at:
**https://www.unb.ca/cic/datasets/iotdataset-2023.html**

### Required Files

After downloading, you need:
- `df_class_8_test.csv` (167MB) - Test set with 25,557 flows
- `df_class_8_train.csv` (981MB) - Training set (optional, only for GNN4ID)

Place these files in a `dataset/` directory at the repository root.

### Dataset Description

CIC-IoT2023 is a comprehensive IoT network traffic dataset containing:
- **8 traffic classes**: Benign, Backdoor, DoS, DDoS, Spoofing, Recon, WebBased, BruteForce
- **97 flow-level features** extracted using CICFlowMeter
- **25,557 test samples** used in our experiments
- Labeled network flows from 105 IoT devices across 33 attack scenarios

### Citation

If you use CIC-IoT2023, please cite:

```bibtex
@dataset{CICIoT2023,
  title={CIC IoT Dataset 2023},
  author={Canadian Institute for Cybersecurity},
  year={2023},
  publisher={University of New Brunswick},
  url={https://www.unb.ca/cic/datasets/iotdataset-2023.html}
}
```

## Ground Truth

This repository includes `compliance_ground_truth.json` - our manually annotated compliance scenarios:
- **30 scenarios** covering all 8 attack classes
- **Expert validated** with Cohen's κ=0.62 inter-annotator agreement
- **Mapped to ETSI EN 303 645** provisions (5.1, 5.3, 5.5, 5.6, 5.7)

Each scenario includes:
- Unique ID
- PCAP scenario description
- ETSI provision reference
- Compliance question
- Ground truth answer
- Attack class label
- Relevant flow features

## File Structure

```
data/
├── README.md (this file)
├── compliance_ground_truth.json (32KB, included)
└── sample_flows.csv (coming soon - small test sample)
```

Note: Download full CIC-IoT2023 dataset separately as instructed above.
