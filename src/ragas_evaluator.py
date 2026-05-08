#!/usr/bin/env python3
"""
RAGAS Evaluation Module

Implements RAGAS (Retrieval-Augmented Generation Assessment Suite) metrics
for evaluating faithfulness of LLM-generated compliance explanations.

Paper: "Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"
Authors: Obrina Briliyant, Amir Javed, Yulia Cherdantseva
"""

import os
from typing import Dict, List, Any
from ragas import evaluate
from ragas.metrics import (
    faithfulness,
    context_precision,
    context_recall,
    answer_correctness,
    answer_relevancy
)
from datasets import Dataset


def create_ragas_dataset(
    questions: List[str],
    answers: List[str],
    contexts: List[List[str]],
    ground_truths: List[str]
) -> Dataset:
    """
    Create RAGAS-compatible dataset from evaluation data.

    Args:
        questions: List of compliance questions
        answers: List of LLM-generated answers
        contexts: List of retrieved contexts (each item is list of context chunks)
        ground_truths: List of ground truth answers

    Returns:
        Dataset: HuggingFace Dataset object ready for RAGAS evaluation
    """
    data = {
        'question': questions,
        'answer': answers,
        'contexts': contexts,
        'ground_truth': ground_truths
    }
    return Dataset.from_dict(data)


def evaluate_with_ragas(
    dataset: Dataset,
    judge_model: str = "gemini-2.0-flash-exp",
    metrics: list = None
) -> Dict[str, float]:
    """
    Evaluate RAG pipeline using RAGAS metrics.

    Args:
        dataset: RAGAS-compatible dataset
        judge_model: LLM model for evaluation (default: Gemini 2.0 Flash)
        metrics: List of RAGAS metrics to compute (default: all 5)

    Returns:
        dict: Dictionary of metric scores
    """
    if metrics is None:
        metrics = [
            faithfulness,
            context_precision,
            context_recall,
            answer_correctness,
            answer_relevancy
        ]

    # Configure judge LLM
    os.environ['OPENAI_API_KEY'] = os.getenv('GOOGLE_API_KEY', '')

    # Run evaluation
    result = evaluate(
        dataset=dataset,
        metrics=metrics,
        llm=judge_model
    )

    return result


def compute_aggregated_metrics(results: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
    """
    Compute mean and standard deviation for each metric across multiple evaluations.

    Args:
        results: List of RAGAS evaluation results

    Returns:
        dict: Aggregated statistics (mean, std, min, max) per metric
    """
    import numpy as np

    metrics = ['faithfulness', 'context_precision', 'context_recall',
               'answer_correctness', 'answer_relevancy']

    aggregated = {}
    for metric in metrics:
        values = [r.get(metric, 0.0) for r in results if metric in r]
        if values:
            aggregated[metric] = {
                'mean': np.mean(values),
                'std': np.std(values),
                'min': np.min(values),
                'max': np.max(values),
                'count': len(values)
            }

    return aggregated


def interpret_faithfulness(score: float) -> str:
    """
    Interpret faithfulness score for compliance auditing context.

    Args:
        score: Faithfulness score (0-1)

    Returns:
        str: Interpretation and recommendation
    """
    if score >= 0.7:
        return "High faithfulness - suitable for automated compliance reporting"
    elif score >= 0.5:
        return "Moderate faithfulness - requires human review before reporting"
    elif score >= 0.3:
        return "Low faithfulness - significant hallucination risk, manual audit recommended"
    else:
        return "Very low faithfulness - unsuitable for compliance use, regenerate with better context"
