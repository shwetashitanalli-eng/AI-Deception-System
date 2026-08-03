#!/usr/bin/env python3
"""
generate_token.py
Simple script to generate a decoy file (canary token) and print its path.
Replace or extend with integration to a real canary/token service if needed.
"""
import os
import uuid
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent

def generate_token(name_prefix="canary",
                   extension="txt"):
    token = f"{name_prefix}_{uuid.uuid4().hex}.{extension}"
    path = OUTPUT_DIR / token
    path.write_text("This is a canary token file. Do not modify.")
    return path

if __name__ == "__main__":
    p = generate_token()
    print(f"Generated canary token: {p}")
