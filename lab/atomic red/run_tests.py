# Trigger Atomic Red Team tests locally
import subprocess
import os
import sys

ATOMIC_TESTS_DIR = os.path.join(os.path.dirname(__file__), "atomics")

def run_atomic_test(test_path):
    print(f"[*] Running Atomic Test: {test_path}")
    try:
        # Assuming tests are PowerShell scripts or YAML with a runner
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", test_path],
            check=True, capture_output=True, text=True
        )
        print("[+] Test Output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("[!] Test failed:", e)
        print("[!] Error Output:\n", e.stderr)

def main():
    if not os.path.exists(ATOMIC_TESTS_DIR):
        print(f"No 'atomics' directory found at {ATOMIC_TESTS_DIR}")
        sys.exit(1)

    # Find all PowerShell scripts or YAMLs to run
    test_files = []
    for root, dirs, files in os.walk(ATOMIC_TESTS_DIR):
        for file in files:
            if file.endswith('.ps1'):  # Adjust as needed for your atomic test format
                test_files.append(os.path.join(root, file))

    if not test_files:
        print("No atomic test scripts found to run.")
        sys.exit(0)

    for test_file in test_files:
        run_atomic_test(test_file)

if __name__ == "__main__":
    main()
