# Pipeline Execution Guide

### 0. Prerequisites (Java 17+)

The OWASP Benchmark requires **Java 17** or higher for the build. If you are on WSL (Ubuntu/Debian), follow these steps to update:

1.  **Check your current version:**

    ```bash
    java -version
    ```

2.  **Install OpenJDK 17:**

    ```bash
    sudo apt update
    sudo apt install openjdk-17-jdk openjdk-17-jre
    ```

3.  **Configure default version (if necessary):**

    ```bash
    sudo update-alternatives --config java
    # Select the number corresponding to java-17-openjdk
    ```

4.  **Verify again:**
    ```bash
    java -version
    # Should show "openjdk version 17..."
    ```

### 1. Pipeline Installation

This document describes the step-by-step process to configure and run the OWASP Benchmark analysis pipeline.

## Prerequisites

Before starting, ensure you have installed on your system:

- **Linux** (Ubuntu/Debian recommended)
- **Java 17+** (Required to run CodeQL and compile the Benchmark)
- **Maven** (To compile the Java project)
- **Python 3.8+**
- **Git**

## Installation and Configuration

The project includes an automatic configuration script that facilitates the entire process.

1.  **Access the pipeline folder:**

    ```bash
    cd pipeline
    ```

2.  **Run the setup script:**
    This script will create the Python virtual environment, install dependencies, download CodeQL, and compile the OWASP Benchmark.

    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```

    _Wait for completion. Benchmark compilation may take a few minutes._

3.  **Configure API Keys (For LLMs):**
    If you intend to run Gemini or GPT, export your API keys as environment variables:
    ```bash
    export OPENAI_API_KEY="your-key-here"
    export GEMINI_API_KEY="your-key-here"
    ```

## Running the Analysis

The `run_pipeline.py` script is the single entry point for all analyses.

### 2. Execution Commands

You can run all tools at once or individually using the wrapper script `run.sh`, which automatically manages the virtual environment.

**Run EVERYTHING (CodeQL, Semgrep, Gemini, GPT):**

```bash
./run.sh --tool all
```

**Run only CodeQL:**

```bash
./run.sh --tool codeql
```

**Run only Semgrep:**

```bash
./run.sh --tool semgrep
```

**Run only Gemini:**

```bash
./run.sh --tool gemini
```

**Run only GPT:**

```bash
./run.sh --tool gpt
```

## Where to find results?

After execution, check the `results/` folder (located one level above the `pipeline` folder).

- **Consolidated Reports:** Look for `*_summary_report.txt` files inside each tool's folder.
- **Raw Data:** The `.sarif`, `.jsonl`, and `.csv` files contain the original data for auditing.

## Common Troubleshooting

- **"Java not found" Error:** Install JDK 17 or higher (`sudo apt install openjdk-17-jdk`).
- **"Maven not found" Error:** Install Maven (`sudo apt install maven`).
- **API Error (Rate Limit):** If GPT or Gemini fail with error 429, edit the files in `pipeline/tools/` and reduce the `MAX_CONCURRENT_TASKS` variable or add a `time.sleep`.
- **CodeQL build failing:** Ensure that the command `mvn clean package` runs successfully manually inside the `owasp-benchmark` folder.
