import oqs

alg = "ML-DSA-44"

with oqs.Signature(alg) as signer:
    pk = signer.generate_keypair()          # This works in your binding

    print("Public key (hex):", pk.hex())
    print("Length PK:", len(pk))

    # Extract secret key safely
    if hasattr(signer, 'secret_key') and signer.secret_key is not None:
        sk = bytes(signer.secret_key)       # Convert C array to bytes
    elif hasattr(signer, 'export_secret_key'):
        sk = signer.export_secret_key()
    else:
        print("Warning: Could not access secret_key directly.")
        sk = b''

    print("Secret key length:", len(sk))

    # Save keys
    with open("oqs_keys.txt", "w") as f:
        f.write(f"PK:{pk.hex()}\n")
        if sk:
            f.write(f"SK:{sk.hex()}\n")
        else:
            f.write("SK:NOT_EXTRACTABLE\n")

print("Keys saved to oqs_keys.txt")
