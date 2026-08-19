import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml_engine import ingest_simulator as ingest


def test_heuristic_score_bounds():
    evt = {
        'failed_login_attempts': 0,
        'command_count': 0,
        'session_duration_seconds': 0,
        'suspicious_command_count': 0,
        'canary_triggered': False
    }
    assert 0 <= ingest.heuristic_score(evt) <= 100


def test_heuristic_score_canary_boost():
    evt = {
        'failed_login_attempts': 0,
        'command_count': 0,
        'session_duration_seconds': 0,
        'suspicious_command_count': 0,
        'canary_triggered': True
    }
    score = ingest.heuristic_score(evt)
    assert score >= 70


def test_classify_severity():
    assert ingest.classify_severity(85) == 'Critical'
    assert ingest.classify_severity(70) == 'High'
    assert ingest.classify_severity(40) == 'Medium'
    assert ingest.classify_severity(10) == 'Low'


def test_classify_type_bruteforce_and_recon():
    evt = {'failed_login_attempts': 200, 'suspicious_command_count': 0, 'command_count': 0, 'session_duration_seconds':0}
    assert ingest.classify_type(evt) == 'Brute Force Attack'

    evt2 = {'failed_login_attempts': 0, 'suspicious_command_count': 6, 'command_count': 30, 'session_duration_seconds':0}
    assert ingest.classify_type(evt2) == 'Reconnaissance/Exploitation'
