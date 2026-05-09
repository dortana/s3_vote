#!/usr/bin/env bash
set -e

export PYTHONDONTWRITEBYTECODE=1

source "$(dirname "$0")/venv/bin/activate"

python api/app.py
