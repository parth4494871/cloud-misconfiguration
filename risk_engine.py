SEVERITY_PENALTIES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def calculate_risk(findings):
    penalty = 0

    for finding in findings:
        severity = finding["severity"]
        penalty += SEVERITY_PENALTIES.get(severity, 0)

    score = max(0, 100 - penalty)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    elif score >= 40:
        grade = "E"
    else:
        grade = "F"

    return score, grade