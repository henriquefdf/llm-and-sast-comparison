#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
CODEQL_HOME="$TOOLS_DIR/codeql-home"
CODEQL_ZIP="codeql-linux64.zip"
CODEQL_URL="https://github.com/github/codeql-cli-binaries/releases/download/v2.23.5/codeql-linux64.zip"
VENV_DIR="$SCRIPT_DIR/venv-pipeline"
BENCHMARK_DIR="$SCRIPT_DIR/../owasp-benchmark"
BENCHMARK_REPO="https://github.com/OWASP-Benchmark/BenchmarkJava.git"

echo "Starting Pipeline Setup..."

# 0. Clone OWASP Benchmark (if not exists)
if [ ! -d "$BENCHMARK_DIR" ]; then
    echo "OWASP Benchmark not found. Cloning..."
    git clone "$BENCHMARK_REPO" "$BENCHMARK_DIR"
else
    echo "OWASP Benchmark already exists."
fi

# 1. Check for Java and Maven
if ! command -v java &> /dev/null; then
    echo "[ERROR] Java is not installed. Please install Java 17+."
    exit 1
fi
if ! command -v mvn &> /dev/null; then
    echo "[ERROR] Maven is not installed. Please install Maven."
    exit 1
fi
echo "Java and Maven found."

# 2. Setup CodeQL
mkdir -p "$TOOLS_DIR"
if [ ! -d "$CODEQL_HOME/codeql" ]; then
    echo "CodeQL not found. Downloading..."
    mkdir -p "$CODEQL_HOME"
    curl -L -o "$CODEQL_HOME/$CODEQL_ZIP" "$CODEQL_URL"
    echo "  Unzipping CodeQL..."
    unzip -q "$CODEQL_HOME/$CODEQL_ZIP" -d "$CODEQL_HOME"
    rm "$CODEQL_HOME/$CODEQL_ZIP"
    echo "CodeQL installed."
else
    echo "CodeQL already installed."
fi

# 3. Setup Python Virtual Environment
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
echo "Installing Python dependencies..."
pip install --upgrade pip > /dev/null
pip install -r "$SCRIPT_DIR/requirements.txt"
echo "Python dependencies installed."

# 4. Download CodeQL Queries
echo "Downloading CodeQL Java Queries..."
"$CODEQL_HOME/codeql/codeql" pack download codeql/java-queries
echo "CodeQL Queries downloaded."

echo "Setup Complete!"
