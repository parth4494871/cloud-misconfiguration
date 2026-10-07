"""
risk_engine.py — Calculates a risk score and letter grade.

HOW SCORING WORKS:
  - Start with 100 points (perfect score).
  - Subtract points for each finding based on severity:
      CRITICAL = -15 points
      HIGH     = -8 points
      MEDIUM   = -3 points
      LOW      = -1 point
  - Score = max(0, 100 − total_penalty)
  - Grade based on score:
      A = 90-100 (Excellent)
      B = 80-89  (Good)
      C = 70-79  (Fair)
      D = 60-69  (Poor)
      F = 0-59   (Failing)
"""

# Severity weights: how many points each severity level costs
SEVERITY_WEIGHTS = {
    'CRITICAL': 15,
    'HIGH': 8,
    'MEDIUM': 3,
    'LOW': 1,
}


def calculate_risk(findings):
    """
    Calculate the risk score and grade from a list of findings.

    Args:
        findings: list of dicts, each with a 'severity' key

    Returns:
        (score, grade) tuple — e.g. (72, 'C')
    """
    # Add up the total penalty from all findings
    total_penalty = 0
    for finding in findings:
        severity = finding.get('severity', 'LOW').upper()
        total_penalty += SEVERITY_WEIGHTS.get(severity, 1)

    # Score is 100 minus the penalty, but never below 0
    score = max(0, 100 - total_penalty)

    # Determine the letter grade
    if score >= 90:
        grade = 'A'
    elif score >= 80:
        grade = 'B'
    elif score >= 70:
        grade = 'C'
    elif score >= 60:
        grade = 'D'
    else:
        grade = 'F'

    return score, grade


def get_severity_counts(findings):
    """
    Count how many findings exist for each severity level.
    Returns a dict like {'CRITICAL': 2, 'HIGH': 3, 'MEDIUM': 1, 'LOW': 0}
    """
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        severity = finding.get('severity', 'LOW').upper()
        if severity in counts:
            counts[severity] += 1
    return counts
