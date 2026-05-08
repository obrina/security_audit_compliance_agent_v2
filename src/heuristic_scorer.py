#!/usr/bin/env python3
"""
Heuristic Anomaly Scoring Module

Implements NetTraceAgentix-inspired flow-level anomaly scoring for IoT network traffic.
Adapted from packet-level heuristics to CIC-IoT2023 flow features.

Paper: "Towards Responsible AI for IoT Network Security Auditing using Knowledge Graphs and RAGAS"
Authors: Obrina Briliyant, Amir Javed, Yulia Cherdantseva
"""

from typing import Dict, Any


def calculate_anomaly_score(features: Dict[str, Any], attack_class: str) -> float:
    """
    Calculate anomaly score for a network flow using heuristic rules.

    Adapted from NetTraceAgentix packet-level weights to flow-level features:
    - High retransmission/ACK activity → retransmission weight (8)
    - High SYN counts → suspicious-flags weight (12)
    - UDP flood patterns → fragment weight (12)
    - Port scanning patterns → reconnaissance weight (10)

    Args:
        features: Dictionary of CIC-IoT2023 flow features
        attack_class: Ground truth attack classification

    Returns:
        float: Anomaly score (0-100+)
    """
    score = 0.0

    # High retransmission/ACK activity (proxy for packet loss/retrans)
    if features.get('Rolling_ACK_Sum', 0) > 300:
        score += 8

    # High SYN count (potential SYN flood or scan)
    if features.get('Rolling_SYN_Sum', 0) > 300:
        score += 12

    # High UDP packet rate (potential UDP flood)
    if features.get('Rolling_UDP_Sum', 0) > 200:
        score += 12

    # Port diversity (reconnaissance behavior)
    if features.get('bidirectional_unique_dst_ports', 0) > 10:
        score += 10

    # Connection establishment anomalies
    init_attempts = features.get('src2dst_syn_packets', 0)
    responses = features.get('dst2src_syn_packets', 0)
    if init_attempts > 0 and responses == 0:
        score += 15  # No response to connection attempts

    # Packet size anomalies
    if features.get('Exp_packet_size_variation', 0) > 1000:
        score += 5

    # High connection rate
    if features.get('Rolling_IP_Sum', 0) > 100:
        score += 7

    # DNS query anomalies
    if features.get('Rolling_DNS_Query_Sum', 0) > 50:
        score += 6

    return score


def score_to_severity(score: float) -> str:
    """
    Convert anomaly score to severity level.

    Args:
        score: Anomaly score from calculate_anomaly_score()

    Returns:
        str: Severity level (Low/Medium/High/Critical)
    """
    if score >= 50:
        return "Critical"
    elif score >= 30:
        return "High"
    elif score >= 15:
        return "Medium"
    else:
        return "Low"


def retrieve_top_flows(df, attack_class: str, top_k: int = 5) -> list:
    """
    Retrieve top-k flows with highest anomaly scores for given attack class.

    Args:
        df: DataFrame with CIC-IoT2023 features
        attack_class: Target attack class
        top_k: Number of flows to retrieve

    Returns:
        list: Top-k flows sorted by anomaly score (descending)
    """
    flows = df[df['Label'] == attack_class].copy()

    # Calculate scores for all flows
    flows['anomaly_score'] = flows.apply(
        lambda row: calculate_anomaly_score(row.to_dict(), attack_class),
        axis=1
    )

    # Sort and return top-k
    return flows.nlargest(top_k, 'anomaly_score').to_dict('records')
