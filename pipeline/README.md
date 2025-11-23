# OWASP Benchmark Analysis Pipeline

This project implements an automated pipeline to execute and compare Static Application Security Testing (SAST) tools and Large Language Models (LLMs) against the [OWASP Benchmark](https://github.com/OWASP/BenchmarkJava).

The goal is to evaluate the effectiveness of different approaches in detecting vulnerabilities in Java code.

## Pipeline Architecture

The pipeline is modular and organized as follows:

- **Orchestrator (`run_pipeline.py`)**: Central script that manages tool execution and result processing.
- **Setup (`setup.sh`)**: Automation script that prepares the environment, installs dependencies, downloads CodeQL, and compiles the Benchmark.
- **Tools (`tools/`)**: Adapter modules for each tool (Semgrep, Gemini, GPT).
- **Utils (`utils/`)**: Utilities for log parsing (SARIF, JSONL) and comparison metrics generation.

## Implemented Tools

- **Java 17+**: Required to compile the OWASP Benchmark (due to the `spotless` plugin).
- **Maven**: To manage the Java project build.

1.  **CodeQL**:

    - Uses the official CodeQL CLI.
    - Runs the `java-security-extended` suite.
    - Results exported in SARIF and converted to CSV.

2.  **Semgrep**:

    - Runs standard security rules (`--config=auto`).
    - Processes JSON output to extract CWE metadata.

3.  **Gemini (Google)**:

    - Model: `gemini-2.5-flash`.
    - Analyzes each test file individually, with dependency context (helpers).
    - Prompt optimized to act as a security auditor.

4.  **GPT (OpenAI)**:
    - Model: `gpt-4o-mini`.
    - Asynchronous parallel execution for high performance.
    - Same prompt structure and context as Gemini for fair comparison.

## Example Results

After execution, results are organized in the `results/` folder. Below is an example of how reports are generated.

### Generated Folder Structure

```text
results/
├── codeql/
│   ├── codeql_results.sarif
│   ├── codeql_results.csv
│   ├── CodeQL_detailed_results.csv
│   └── CodeQL_summary_report.txt
├── semgrep/
│   └── ...
├── gemini/
│   └── ...
└── gpt/
│   └── ...
```

### Example Summary Report (`summary_report.txt`)

```text
--- Performance Report: GPT-5-mini ---
===========================================
Analysis Mode: RELAXED (Any CWE counts as TP)
===========================================

--- CONSOLIDATED METRICS ---
Total Test Cases Analyzed: 2740
True Positives (TP):  1150
False Positives (FP):  420
False Negatives (FN):  250
True Negatives (TN):   920
------------------------------
Precision: 73.25%
Recall:    82.14%
F1-Score:  77.44%
False Positive Rate: 31.34%

===========================================

--- BREAKDOWN BY CWE (Target) ---
Note: TPs based on RELAXED criteria (Any CWE counts as TP)

  CWE-022: 	Hits (TP): 150 | Misses (FN):  20 (out of 170 cases)
  CWE-078: 	Hits (TP): 200 | Misses (FN):  10 (out of 210 cases)
  CWE-089: 	Hits (TP): 300 | Misses (FN):  50 (out of 350 cases)
  ...

--- DETECTIONS IN SECURE CODE (False Positives) ---
  CWE-022: 	50 incorrect detections.
  CWE-089: 	120 incorrect detections.
  ...
```

### Example Detailed CSV (`detailed_results.csv`)

| test_case_id | status | is_truly_vulnerable | target_cwe | tool_detected_any_vuln | tool_detected_correct_cwe |
| :----------- | :----- | :------------------ | :--------- | :--------------------- | :------------------------ |
| 00001        | TP     | True                | 022        | True                   | True                      |
| 00002        | FN     | True                | 078        | False                  | False                     |
| 00003        | TN     | False               | 089        | False                  | False                     |
| 00004        | FP     | False               | 089        | True                   | True                      |

## Expected Comparison

By the end of the pipeline, you will have enough data to answer questions like:

- Which tool has the best detection rate (Recall)?
- Which tool generates the least noise (lowest False Positive Rate)?
- Can LLMs outperform traditional tools (SAST) in complex data flow cases?
