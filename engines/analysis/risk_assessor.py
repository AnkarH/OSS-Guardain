#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Risk Assessor
Calculates risk score (0-100) based on threat count and severity.
"""

from typing import List, Dict, Any


def assess_risk(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Assess risk based on identified threats.
    
    Args:
        threats: List of threat dictionaries from threat_identifier.identify_threats()
        
    Returns:
        dict: Risk assessment containing:
            - 'risk_score': int - Risk score (0-100)
            - 'risk_level': str - Risk level ('low', 'medium', 'high', 'critical')
            - 'threat_count': int - Total number of threats
            - 'breakdown': dict - Count by severity
    """
    # Scoring rules
    SCORE_CRITICAL = 30
    SCORE_HIGH = 15
    SCORE_MEDIUM = 5
    SCORE_LOW = 1
    MAX_SCORE = 100
    
    # Count threats by severity
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for threat in threats:
        severity = threat.get('severity', 'medium').lower()
        if severity == 'critical':
            critical_count += 1
        elif severity == 'high':
            high_count += 1
        elif severity == 'medium':
            medium_count += 1
        else:
            low_count += 1
    
    # Calculate risk score
    risk_score = (
        critical_count * SCORE_CRITICAL +
        high_count * SCORE_HIGH +
        medium_count * SCORE_MEDIUM +
        low_count * SCORE_LOW
    )
    
    # Cap at maximum
    risk_score = min(risk_score, MAX_SCORE)
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = 'critical'
    elif risk_score >= 50:
        risk_level = 'high'
    elif risk_score >= 20:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'threat_count': len(threats),
        'breakdown': {
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        }
    }
