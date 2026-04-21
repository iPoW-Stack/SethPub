"""
Run all Seth chain tests.
Usage:
  python tests/run_all.py                          # offline tests only
  SETH_HOST=35.197.170.240 python tests/run_all.py # all tests including on-chain
"""
import subprocess, sys, os, time

TESTS = [
    ("BasicTests/test_keyaddr.py", False),
    ("BasicTests/test_transaction.py", False),
    ("ABITests/test_abi_encoding.py", False),
    ("TransactionTests/test_signature.py", False),
    ("TransactionTests/test_address_nonce_value.py", False),
    ("GenesisTests/test_genesis.py", True),
    ("BlockchainTests/VMTests/test_vm_opcodes.py", True),
    ("BlockchainTests/StateTests/test_create2.py", True),
    ("BlockchainTests/StateTests/test_revert.py", True),
    ("BlockchainTests/StateTests/test_call_codes.py", True),
    ("BlockchainTests/StateTests/test_precompiles.py", True),
    ("BlockchainTests/StateTests/test_storage.py", True),
    ("BlockchainTests/StateTests/test_log_shift.py", True),
    ("BlockchainTests/StateTests/test_code_env.py", True),
    ("BlockchainTests/StateTests/test_system_ops.py", True),
    ("BlockchainTests/StateTests/test_static_delegate.py", True),
    ("BlockchainTests/StateTests/test_memory_stack.py", True),
    ("BlockchainTests/StateTests/test_create_refund.py", True),
    ("BlockchainTests/StateTests/test_zero_boundary.py", True),
    ("BlockchainTests/StateTests/test_attack_badop.py", True),
    ("BlockchainTests/StateTests/test_solidity_codelimit.py", True),
]

def main():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    has_host = bool(os.getenv("SETH_HOST"))
    total_pass = 0
    total_fail = 0
    total_skip = 0
    results = []

    for test_file, needs_chain in TESTS:
        if needs_chain and not has_host:
            results.append((test_file, "SKIP", "needs SETH_HOST"))
            total_skip += 1
            continue

        path = os.path.join(test_dir, test_file)
        if not os.path.exists(path):
            results.append((test_file, "SKIP", "file not found"))
            total_skip += 1
            continue

        print(f"\n{'='*60}")
        print(f"Running: {test_file}")
        print('='*60)

        try:
            r = subprocess.run([sys.executable, path], timeout=300,
                               capture_output=False, env=os.environ.copy())
            if r.returncode == 0:
                results.append((test_file, "PASS", ""))
                total_pass += 1
            else:
                results.append((test_file, "FAIL", f"exit code {r.returncode}"))
                total_fail += 1
        except subprocess.TimeoutExpired:
            results.append((test_file, "TIMEOUT", ""))
            total_fail += 1
        except Exception as e:
            results.append((test_file, "ERROR", str(e)))
            total_fail += 1

    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    for test_file, status, detail in results:
        icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊘", "TIMEOUT": "⏱", "ERROR": "⚠"}[status]
        line = f"  {icon} {status:7s} {test_file}"
        if detail:
            line += f"  ({detail})"
        print(line)

    print(f"\n  Total: {total_pass} passed, {total_fail} failed, {total_skip} skipped")
    return total_fail

if __name__ == "__main__":
    sys.exit(main())
