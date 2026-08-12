"""
attack_simulator.py

Simulate SSH login attempts and file drop triggers against the honeypot for testing the pipeline.
"""

import random
import time


def simulate_one_attempt():
    # Placeholder simulator logic
    print("Simulating attack attempt")


if __name__ == "__main__":
    for _ in range(3):
        simulate_one_attempt()
        time.sleep(0.5)
