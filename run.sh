#!/usr/bin/env bash
set -e

source "$(dirname "$0")/venv/bin/activate"

python api/app.py
