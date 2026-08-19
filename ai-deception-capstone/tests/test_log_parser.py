import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml_engine import log_parser as lp


def test_extract_features_from_json_valid():
    event = {
        'timestamp': '2026-01-01T00:00:00Z',
        'ip': '1.2.3.4',
        'commands': ['ls', 'whoami', 'nmap -sV localhost'],
        'session_duration': 120,
        'failed_logins': 0
    }
    rec = lp.extract_features_from_json(event)
    assert rec is not None
    assert rec['source_ip'] == '1.2.3.4'
    assert rec['command_count'] == 3
    assert rec['suspicious_command_count'] >= 1


def test_extract_features_from_json_missing_ip():
    event = {'commands': ['ls']}
    rec = lp.extract_features_from_json(event)
    assert rec is None


def test_count_suspicious_commands():
    cmds = ['nmap -sV', 'ls', 'curl http://example.com', 'echo hello']
    assert lp.count_suspicious_commands(cmds) == 2
