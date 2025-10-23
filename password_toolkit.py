import math
import json
import sys
import os
import hashlib
import time
import argparse
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

####Start of Task 1 (Password Meter)####
def char_pool(pw: str) -> int:
    pool_size = 0
    if any(c.islower() for c in pw):
        pool_size += 26
    if any(c.isupper() for c in pw):
        pool_size += 26
    if any(c.isdigit() for c in pw):
        pool_size += 10
    if any(not c.isalnum() for c in pw):
        pool_size += 32
    if pool_size ==0:
        pool_size = 1
    return pool_size

def entropy(pw: str) -> float:
    pool_size = char_pool(pw)
    length = len(pw)
    return 0.0 if length == 0 else length * math.log2(pool_size)

def pw_rating(entropy: float) -> str:
    if entropy < 28:
        return "weak"
    elif entropy <= 35:
        return "fair"
    elif entropy <= 59:
        return "good"
    return "strong"

def pw_meter(pw: str) -> dict:
    ent = entropy(pw)
    rating = pw_rating(ent)
    suggestions = []
    suggestions.extend(repeat_detection(pw))
    suggestions.extend(sequence_detection(pw))
    suggestions.extend(common_substring_detection(pw))
    suggestions.extend(years_detection(pw))

    seen = set()
    deduped = []
    for s in suggestions:
        if s not in seen:
            deduped.append(s)
            seen.add(s)

    return {
        "entropy": round(ent, 2),
        "rating": rating,
        "suggestions": deduped
    }

def repeat_detection(pw: str) -> list:
    if not pw:
        return []
    suggestions = []
    max_run = 1
    cur_run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            cur_run += 1
            if cur_run > max_run:
                max_run = cur_run
        else:
            cur_run = 1
    if max_run >= 3:
        suggestions.append(f"avoid repeated characters (found a run of {max_run})")
    return suggestions

def sequence_detection(pw: str) -> list:
    if not pw:
        return []

    def char_type(ch):
        if ch.isalpha():
            return "alpha"
        if ch.isdigit():
            return "digit"
        return None

    def norm_value(ch):
        if ch.isalpha():
            return ord(ch.lower())
        if ch.isdigit():
            return ord(ch)
        return None

    max_run = 1
    cur_run = 1
    max_example = pw[0]
    cur_example = pw[0]
    prev_type = char_type(pw[0])
    prev_val = norm_value(pw[0])
    prev_step = None

    for i in range(1, len(pw)):
        ch_type = char_type(pw[i])
        ch_val = norm_value(pw[i])

        if ch_type == prev_type and ch_val is not None and prev_val is not None:
            step = ch_val - prev_val
            if step in (1, -1) and (prev_step is None or step == prev_step):
                cur_run += 1
                cur_example += pw[i]
                prev_step = step
            else:
                if cur_run > max_run:
                    max_run = cur_run
                    max_example = cur_example
                cur_run = 1
                cur_example = pw[i]
                prev_step = None
        else:
            if cur_run > max_run:
                max_run = cur_run
                max_example = cur_example
            cur_run = 1
            cur_example = pw[i]
            prev_step = None

        prev_type = ch_type
        prev_val = ch_val

    if cur_run > max_run:
        max_run = cur_run
        max_example = cur_example

    suggestions = []
    if max_run >= 3:
        example = ''.join(c.lower() if c.isalpha() else c for c in max_example)
        suggestions.append(
            f"avoid sequences like 'abc' or '321' (found a run of {max_run}: '{example}')"
        )
    return suggestions

def common_substring_detection(pw: str, common_subs: set | None = None) -> list:
    if not pw:
        return []

    if common_subs is None:
        common_subs = {
            "password", "pass", "admin", "qwerty", "letmein",
            "welcome", "iloveyou", "dragon", "football"
        }

    pw_lower = pw.lower()
    hits = [sub for sub in common_subs if sub in pw_lower]

    suggestions = []
    if hits:
        joined_hits = ", ".join(f"'{h}'" for h in hits)
        suggestions.append(f"avoid common substrings like {joined_hits}")

    return suggestions

def years_detection(pw: str) -> list:
    suggestions = []
    for year in range(1900, 2100):
        year_str = str(year)
        if year_str in pw:
            suggestions.append(f"avoid using years like '{year_str}'")
    suggestions = sorted(list(set(suggestions)))
    return suggestions
####End of Task 1 (Password Meter)####

####Start of Task 2 (Hashing and Storage)####
def pbkdf2_hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> tuple[bytes, bytes, int]:
    if salt is None:
        salt = get_random_bytes(16)
    dk = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    return salt, dk, iterations

def pbkdf2_verify_password(password: str, salt_hex: str, hash_hex: str, iterations: int) -> bool:
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    dk = PBKDF2(password, salt, dkLen=len(expected), count=iterations, hmac_hash_module=SHA256)
    return dk == expected

def load_users_json(path: str = "data/sample_users.json") -> dict:
    if not os.path.exists(os.path.dirname(path)) and os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users_json(data: dict, path: str = "data/sample_users.json") -> None:
    if not os.path.exists(os.path.dirname(path)) and os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def create_or_update_user(username: str, password: str, path: str = "data/sample_users.json") -> dict:
    users = load_users_json(path)
    pwd_salt, pwd_hash, pwd_iters = pbkdf2_hash_password(password, iterations=200_000)
    kdf_salt, _, kdf_iters = pbkdf2_hash_password(password, iterations=200_000)
    entry = users.get(username, {})
    entry["pwd_salt_hex"] = pwd_salt.hex()
    entry["pwd_hash_hex"] = pwd_hash.hex()
    entry["pwd_iterations"] = pwd_iters
    entry["kdf_salt_hex"] = kdf_salt.hex()
    entry["kdf_iterations"] = kdf_iters
    if "enc_counter" not in entry:
        entry["enc_counter"] = 0
    users[username] = entry
    save_users_json(users, path)
    return entry
####End of Task 2 (Hashing and Storage)####

####Start of Task 3 (Bloom Filter)####
def bloom_size_for(n: int, target_fpr: float = 0.01) -> tuple[int, int]:
    if n <= 0:
        return 1024, 3
    m = int(math.ceil(-(n * math.log(target_fpr)) / (math.log(2) ** 2)))
    k = max(1, int(round((m / n) * math.log(2))))
    return m, k

class BloomFilter:
    def __init__(self, m_bits: int, k_funcs: int):
        self.m = m_bits
        self.k = k_funcs
        self.bytes_len = (self.m + 7) // 8
        self.bits = bytearray(self.bytes_len)
    def _set_bit(self, idx: int):
        byte_index = idx // 8
        bit_index = idx % 8
        self.bits[byte_index] |= (1 << bit_index)
    def _get_bit(self, idx: int) -> bool:
        byte_index = idx // 8
        bit_index = idx % 8
        return (self.bits[byte_index] >> bit_index) & 1 == 1
    def _hash_indices(self, s: str):
        b = s.encode("utf-8")
        for i in range(self.k):
            h = hashlib.sha256(i.to_bytes(2, "big") + b).digest()
            idx = int.from_bytes(h[:8], "big") % self.m
            yield idx
    def add(self, s: str):
        for idx in self._hash_indices(s):
            self._set_bit(idx)
    def probably_contains(self, s: str) -> bool:
        for idx in self._hash_indices(s):
            if not self._get_bit(idx):
                return False
        return True

def build_bloom_from_file(blacklist_path: str, target_fpr: float = 0.01) -> BloomFilter:
    n = 0
    with open(blacklist_path, "r", encoding="utf-8", errors="ignore") as f:
        for _ in f:
            n += 1
    m, k = bloom_size_for(n, target_fpr=target_fpr)
    bf = BloomFilter(m, k)
    with open(blacklist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\n")
            if pw:
                bf.add(pw)
    return bf

def save_bloom(bf: BloomFilter, path: str = "data/bloom.bin") -> None:
    with open(path, "wb") as f:
        f.write(bf.m.to_bytes(8, "big"))
        f.write(bf.k.to_bytes(4, "big"))
        f.write(bf.bits)

def load_bloom(path: str = "data/bloom.bin") -> BloomFilter:
    with open(path, "rb") as f:
        m = int.from_bytes(f.read(8), "big")
        k = int.from_bytes(f.read(4), "big")
        bits = bytearray(f.read())
    bf = BloomFilter(m, k)
    if len(bits) == bf.bytes_len:
        bf.bits = bits
    else:
        bf.bits = bits[:bf.bytes_len] + bytearray(max(0, bf.bytes_len - len(bits)))
    return bf

def bloom_reject(password: str, bloom_path: str = "data/bloom.bin") -> bool:
    try:
        bf = load_bloom(bloom_path)
    except FileNotFoundError:
        return False
    return bf.probably_contains(password)
####End of Task 3 (Bloom Filter)####

####Start of Task 4 (Cracker Simulator)####
def simulate_crack(dict_path: str, users_path: str = "data/sample_users.json", max_guesses: int | None = None) -> dict:
    users = load_users_json(users_path)
    targets = {}
    for uname, entry in users.items():
        if all(k in entry for k in ("pwd_salt_hex", "pwd_hash_hex", "pwd_iterations")):
            targets[uname] = (entry["pwd_salt_hex"], entry["pwd_hash_hex"], entry["pwd_iterations"])
    cracked = {}
    tried = 0
    if not os.path.exists(dict_path):
        return {"tried": 0, "cracked": []}
    with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if max_guesses is not None and tried >= max_guesses:
                break
            guess = line.rstrip("\n")
            if not guess:
                continue
            tried += 1
            for uname, (salt_hex, hash_hex, iters) in list(targets.items()):
                if pbkdf2_verify_password(guess, salt_hex, hash_hex, iters):
                    cracked[uname] = guess
                    del targets[uname]
            if not targets:
                break
    cracked_list = [{"username": u, "password": p} for u, p in cracked.items()]
    return {"tried": tried, "cracked": cracked_list}
####End of Task 4 (Cracker Simulator)####

####Start of Task 5 (Encryption)####
def derive_key_for_user(username: str, password: str, users_path: str = "data/sample_users.json") -> bytes:
    users = load_users_json(users_path)
    entry = users.get(username, {})
    kdf_salt_hex = entry.get("kdf_salt_hex")
    kdf_iterations = entry.get("kdf_iterations")
    if not kdf_salt_hex or not kdf_iterations:
        raise ValueError("missing KDF parameters for user")
    salt = bytes.fromhex(kdf_salt_hex)
    key = PBKDF2(password, salt, dkLen=32, count=int(kdf_iterations), hmac_hash_module=SHA256)
    return key

def encrypt_file_for_user(username: str, password: str, in_path: str, out_path: str, aad: str = "", users_path: str = "data/sample_users.json") -> dict:
    key = derive_key_for_user(username, password, users_path)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad.encode("utf-8"))
    with open(in_path, "rb") as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(out_path, "wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)
    users = load_users_json(users_path)
    entry = users.get(username, {})
    entry["enc_counter"] = int(entry.get("enc_counter", 0)) + 1
    users[username] = entry
    save_users_json(users, users_path)
    return {"bytes_in": len(plaintext), "bytes_out": len(ciphertext), "nonce_hex": nonce.hex(), "tag_hex": tag.hex(), "enc_counter": entry["enc_counter"]}

def decrypt_file_for_user(username: str, password: str, in_path: str, out_path: str, aad: str = "", users_path: str = "data/sample_users.json") -> dict:
    key = derive_key_for_user(username, password, users_path)
    with open(in_path, "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad.encode("utf-8"))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    return {"bytes_out": len(plaintext)}
####End of Task 5 (Encryption)####

####Start of Task 6 (Testing)####
def run_tests() -> dict:
    # setup
    os.makedirs("data", exist_ok=True)
    create_or_update_user("testuser", "My$tr0ngPass!")

    # Positive: correct password verifies; encrypt->decrypt equals original
    u = load_users_json().get("testuser")
    ok_verify = pbkdf2_verify_password("My$tr0ngPass!", u["pwd_salt_hex"], u["pwd_hash_hex"], u["pwd_iterations"])
    with open("data/_pos_plain.bin", "wb") as f: f.write(b"hello world! this is a test.")
    enc_info = encrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_pos_plain.bin", "data/_pos_cipher.bin", aad="AAD-OK")
    dec_info = decrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_pos_cipher.bin", "data/_pos_plain_out.bin", aad="AAD-OK")
    ok_eq = open("data/_pos_plain.bin","rb").read() == open("data/_pos_plain_out.bin","rb").read()

    # Negative: wrong password => auth failure
    wrong_pw_failed = False
    try:
        decrypt_file_for_user("testuser", "wrongpass", "data/_pos_cipher.bin", "data/_neg_wrong_out.bin", aad="AAD-OK")
    except Exception:
        wrong_pw_failed = True

    # Negative: bit flip => auth failure
    bit_flip_failed = False
    blob = bytearray(open("data/_pos_cipher.bin","rb").read())
    if len(blob) > 32: blob[32] ^= 0x01
    else: blob[-1] ^= 0x01
    open("data/_neg_flip_cipher.bin","wb").write(blob)
    try:
        decrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_neg_flip_cipher.bin", "data/_neg_flip_out.bin", aad="AAD-OK")
    except Exception:
        bit_flip_failed = True

    # Negative: different AAD => auth failure
    aad_failed = False
    encrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_pos_plain.bin", "data/_neg_aad_cipher.bin", aad="AAD-ONE")
    try:
        decrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_neg_aad_cipher.bin", "data/_neg_aad_out.bin", aad="AAD-TWO")
    except Exception:
        aad_failed = True

    # Performance: record KDF and encryption time for 10 MB
    chunk = os.urandom(1024 * 1024)
    with open("data/_perf_plain.bin","wb") as f:
        for _ in range(10): f.write(chunk)
    t0 = time.perf_counter(); _ = derive_key_for_user("testuser", "My$tr0ngPass!"); t1 = time.perf_counter()
    t2 = time.perf_counter(); encrypt_file_for_user("testuser", "My$tr0ngPass!", "data/_perf_plain.bin", "data/_perf_cipher.bin", aad="AAD-PERF"); t3 = time.perf_counter()

    return {
        "positive": {"verify_ok": ok_verify, "decrypt_bytes_ok": ok_eq},
        "negative": {
            "wrong_password_causes_failure": wrong_pw_failed,
            "bit_flip_causes_failure": bit_flip_failed,
            "aad_mismatch_causes_failure": aad_failed
        },
        "performance": {"kdf_ms": round((t1 - t0) * 1000, 2), "encrypt_ms": round((t3 - t2) * 1000, 2), "size_mb": 10}
    }
####End of Tests####


def main():
    parser = argparse.ArgumentParser(description="ICS344 HW2 Password Toolkit")
    sub = parser.add_subparsers(dest="cmd")

    p_check = sub.add_parser("check-password")
    p_check.add_argument("--password", required=True)

    p_user = sub.add_parser("create-user")
    p_user.add_argument("--username", required=True)
    p_user.add_argument("--password", required=True)

    p_bloom = sub.add_parser("build-bloom")
    p_bloom.add_argument("--blacklist", required=True)
    p_bloom.add_argument("--out", default="data/bloom.bin")

    p_enc = sub.add_parser("encrypt-file")
    p_enc.add_argument("--username", required=True)
    p_enc.add_argument("--password", required=True)
    p_enc.add_argument("--infile", required=True)
    p_enc.add_argument("--outfile", required=True)

    p_dec = sub.add_parser("decrypt-file")
    p_dec.add_argument("--username", required=True)
    p_dec.add_argument("--password", required=True)
    p_dec.add_argument("--infile", required=True)
    p_dec.add_argument("--outfile", required=True)

    p_crack = sub.add_parser("simulate-crack")
    p_crack.add_argument("--dict", required=True)

    p_test = sub.add_parser("test-all")

    args = parser.parse_args()

    if args.cmd == "check-password":
        result = pw_meter(args.password)
        if bloom_reject(args.password):
            result.setdefault("suggestions", []).append(
                "bloom filter: password appears in blacklist (could be false positive)"
            )
        print(json.dumps(result, indent=2))
    elif args.cmd == "create-user":
        if bloom_reject(args.password):
            print(json.dumps({
                "error": "rejected_by_bloom",
                "message": "Password appears in blacklist (Bloom filter). Try a stronger password.",
                "note": "Bloom filters can have false positives (<1% target); if this is a false positive, change the password slightly."
            }, indent=2))
            return
        print(json.dumps(create_or_update_user(args.username, args.password), indent=2))
    elif args.cmd == "build-bloom":
        bf = build_bloom_from_file(args.blacklist)
        save_bloom(bf, args.out)
        print(f"Bloom filter saved to {args.out} (m={bf.m}, k={bf.k})")
    elif args.cmd == "encrypt-file":
        print(json.dumps(encrypt_file_for_user(args.username, args.password, args.infile, args.outfile), indent=2))
    elif args.cmd == "decrypt-file":
        print(json.dumps(decrypt_file_for_user(args.username, args.password, args.infile, args.outfile), indent=2))
    elif args.cmd == "simulate-crack":
        print(json.dumps(simulate_crack(args.dict), indent=2))
    elif args.cmd == "test-all":
        print(json.dumps(run_tests(), indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

