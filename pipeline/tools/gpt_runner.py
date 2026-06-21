import os
import glob
import json
import asyncio
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm

def get_helpers_context(benchmark_dir):
    helpers_dir = os.path.join(benchmark_dir, "src", "main", "java", "org", "owasp", "benchmark", "helpers")
    helpers_content = []
    for file_path in glob.glob(os.path.join(helpers_dir, "*.java")):
        with open(file_path, "r", encoding="utf-8") as f:
            helpers_content.append(f"--- {os.path.basename(file_path)} ---\n" + f.read())
    return "\n\n".join(helpers_content)

async def process_file(client, file_path, system_prompt, semaphore, outfile, processed_files, write_lock, error_log_path):
    file_name = os.path.basename(file_path)
    if file_name in processed_files:
        return
        
    with open(file_path, "r", encoding="utf-8") as f:
        code_content = f.read()
        
    prompt = f"Analyze the following file: {file_name}\n\n<code>\n{code_content}\n</code>"
    
    async with semaphore:
        max_retries = 4
        for attempt in range(max_retries):
            try:
                response = await client.chat.completions.create(
                    model="gpt-5-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                
                result_text = response.choices[0].message.content.strip()
                data = json.loads(result_text)
                
                # Ensure fileName is correct
                data["fileName"] = file_name
                
                # Write synchronously (fast enough for single lines, or could use aiofiles)
                async with write_lock:
                    outfile.write(json.dumps(data) + "\n")
                    outfile.flush()
                break
            except Exception as e:
                async with write_lock:
                    with open(error_log_path, "a", encoding="utf-8") as err_f:
                        err_f.write(f"[{file_name} - Attempt {attempt+1}/{max_retries}] ERROR: {e}\n")
                
                if "429" in str(e):
                    await asyncio.sleep(5 * (attempt + 1))
                else:
                    print(f"Error processing {file_name}: {e}")
                    break
        else:
            msg = f"FATAL: Rate limit persists after {max_retries} retries for {file_name}. You have likely hit your daily quota limit or ran out of credits. Aborting script to avoid silent skips."
            print(msg)
            async with write_lock:
                with open(error_log_path, "a", encoding="utf-8") as err_f:
                    err_f.write(f"{msg}\n")
            os._exit(1)

async def async_run_gpt(output_dir):
    print("Initializing GPT Runner...")
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY not found in environment variables.")
        return None
        
    client = AsyncOpenAI(api_key=api_key)
    
    benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "owasp-benchmark"))
    testcode_dir = os.path.join(benchmark_dir, "src", "main", "java", "org", "owasp", "benchmark", "testcode")
    
    helpers_context = get_helpers_context(benchmark_dir)
    
    system_prompt = f"""You are a senior security auditor analyzing Java code for security vulnerabilities.
You have access to the following helper classes from the project (dependency context):

<helpers>
{helpers_context}
</helpers>

Your task is to analyze the provided Java test case file and identify any security vulnerabilities (CWEs).
You MUST return ONLY a valid JSON object matching exactly this schema, without markdown formatting or code blocks:
{{
  "fileName": "BenchmarkTestXXXX.java",
  "isVulnerable": true,
  "vulnerabilitiesFound": [
    {{"cwe": "CWE-XX", "line": 45}}
  ]
}}
If no vulnerabilities are found, set "isVulnerable" to false and omit the "vulnerabilitiesFound" array.
"""

    jsonl_output = os.path.join(output_dir, "gpt_results.jsonl")
    error_log_path = os.path.join(output_dir, "gpt_errors.log")
    
    processed_files = set()
    if os.path.exists(jsonl_output):
        with open(jsonl_output, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if "fileName" in data:
                        processed_files.add(data["fileName"])
                except json.JSONDecodeError:
                    pass
    
    test_files = glob.glob(os.path.join(testcode_dir, "BenchmarkTest*.java"))
    print(f"Found {len(test_files)} test cases. Resuming from {len(processed_files)} already processed.")
    
    semaphore = asyncio.Semaphore(7)
    write_lock = asyncio.Lock()
    
    with open(jsonl_output, "a", encoding="utf-8") as outfile:
        tasks = [
            process_file(client, file_path, system_prompt, semaphore, outfile, processed_files, write_lock, error_log_path)
            for file_path in test_files
        ]
        
        # Use tqdm to show progress asynchronously
        for f in tqdm.as_completed(tasks, total=len(tasks), desc="Analyzing with GPT"):
            await f
            
    return jsonl_output

def run_gpt(output_dir):
    return asyncio.run(async_run_gpt(output_dir))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_gpt(sys.argv[1])
    else:
        print("Please provide output directory")
