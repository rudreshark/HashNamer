Here is the **entire README** in a single block – ready to copy and paste directly into your `README.md` file on GitHub.

```markdown
# HASHNAMER v4

```
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗███╗   ██╗ █████╗ ███╗   ███╗███████╗██████╗ 
  ██║  ██║██╔══██╗██╔════╝██║  ██║████╗  ██║██╔══██╗████╗ ████║██╔════╝██╔══██╗
  ███████║███████║███████╗███████║██╔██╗ ██║███████║██╔████╔██║█████╗  ██████╔╝
  ██╔══██║██╔══██║╚════██║██╔══██║██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗
  ██║  ██║██║  ██║███████║██║  ██║██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
  ⚡────── v4 · 46 METHODS · HASH CRACKER · HIBP · AUTO-CHAIN ──────⚡
```

**The ultimate CTF multi‑tool:** automatically identify and decode dozens of encoding formats, detect hash types, crack weak passwords using built‑in and system wordlists, and check cracked passwords against the *Have I Been Pwned* database – all with zero user interaction (fully automatic mode).

---

## Features

- 🔍 **46 Detection & Decoding Methods** – BaseXX, Hex, Binary, ROT13/47, Atbash, Caesar, Affine, Vigenère, Rail Fence, Morse, Bacon, NATO, Polybius, A1Z26, T9, Leetspeak, URL‑encode, HTML entities, XOR brute‑force and more.
- 🧠 **Automatic Chaining** – The engine recursively decodes the output until it reaches plain text (or gives up gracefully).
- 🗝️ **Hash Identifier** – Detects 30+ hash types (MD5, SHA1/2/3, NTLM, bcrypt, Argon2, WordPress, Django, etc.).
- 🚀 **Instant Cracking** – No more prompts! Upon hash detection, the tool immediately tries the built‑in wordlist (~130 passwords), then falls back to any system wordlist (rockyou.txt, etc.) it finds automatically.
- 📡 **HIBP Integration** – If a password is cracked, it queries the *Have I Been Pwned* API (k‑anonymity, privacy‑safe) and tells you how many breaches that password has been seen in.
- 🧩 **Multi‑Line Input** – Paste large hex dumps or multi‑line data; the tool handles it.
- 🎨 **Colourful Console** – Uses `colorama` for a beautiful, easy‑to‑read interface.

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/rudreshark/hashnamer.git
cd hashnamer
```

### 2. Install the only external dependency
```bash
pip install colorama   # optional, but recommended for coloured output
```

> **Note:** The tool is written in pure Python 3 and uses only standard libraries except `colorama`. If you don't install it, the tool still works – just without colours.

### 3. (Optional) Install John the Ripper & Hashcat
If you want to use the more advanced cracking engines (not required – the built‑in and system wordlist methods work out of the box):
```bash
sudo apt install john hashcat   # on Debian/Ubuntu
```

---

## Usage

Run the script:
```bash
python3 hashnamer.py
```

You will see a banner and then the interactive prompt:
```
INPUT >
```

Paste any encoded string, hash, ciphertext, or hex dump and press Enter.

### How it works (fully automatic)
1. **Encoding detection** – The tool scans the input against dozens of regular expressions.
2. **Auto‑chaining** – It decodes the input, then re‑scans the result, repeating until no more known patterns are found.
3. **Hash identification** – If the input (or any decoded step) matches a hash signature, it is flagged.
4. **Cracking** – For crackable hashes (MD5, SHA1, NTLM, etc.), the tool instantly:
   - Tries the built‑in wordlist.
   - If not found, scans any system wordlist it finds (rockyou.txt, etc.).
   - Reports the plaintext password and automatically checks it against HIBP.
5. **Final output** – The last decodable / cracked value is shown.

---

## Examples

### 1. Base64 → Hex → Flag
```
INPUT > 666c61677b346e645f30683372357d
```
Output:
```
[STEP 1] Method  : Hex Raw          [█████████▌] 95%
         Result  : flag{4nd_0h3r5}
[FINAL DECODED OUTPUT]
flag{4nd_0h3r5}
```

### 2. Crack an MD5 hash
```
INPUT > e10adc3949ba59abbe56e057f20f883e
```
Output:
```
╔══ HASH IDENTIFIED ══╗
  Type    : MD5
  Value   : e10adc3949ba59abbe56e057f20f883e
  Hashcat : -m 0
[*] Attempting automatic cracking...
[*] Trying built‑in wordlist...
[+] Cracked with built‑in!
══════════════════════════
  CRACKED  ->  123456
══════════════════════════
[*] Checking HIBP breach database...
[HIBP]  Found in 23,451,456 breach(es) — compromised!
```

### 3. Multi‑step ROT13 → Base64 → Text
```
INPUT > Uryyb Jbeyq   (ROT13 of "Hello World")
```
Output:
```
[STEP 1] Method  : ROT13            [████████] 85%
         Result  : Hello World
[FINAL DECODED OUTPUT]
Hello World
```

---

## Supported Formats (46 methods)

| Category                | Methods                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| **Base Encodings**      | Base16, Base32, Base36, Base45, Base58, Base62, Base64, Base64‑URL, Base85 (ASCII85), Base91 |
| **Raw Encodings**       | Hex, Binary, Octal, Decimal                                             |
| **Classical Ciphers**   | ROT13, ROT47, Atbash, Caesar (brute‑force), Affine (brute‑force), Vigenère (brute‑force), Beaufort, Rail Fence (brute‑force) |
| **Modern Ciphers**      | XOR (single‑byte brute‑force with interactive selection)               |
| **Character Codes**     | Morse, Bacon, NATO Phonetic, A1Z26, T9 Keypad, Polybius Square         |
| **Web / Misc**          | URL Percent‑Encoding, HTML Entities, Quoted‑Printable, Scientific Notation, JWT Token, Unicode Escapes, Punycode |
| **LeetSpeak**           | Normalization (4→a, 3→e, etc.)                                          |
| **Other**               | Reverse string, Hex dump offset stripper                                |

---

## Hash Types Detected (36 signatures)

| Hash Type           | Example / Pattern                    | Crackable | Hashcat Mode |
|---------------------|--------------------------------------|-----------|--------------|
| MD5                 | 32 hex chars                         | ✅        | 0            |
| MD4                 | 32 hex chars                         | ✅        | 900          |
| NTLM                | 32 hex chars                         | ✅        | 1000         |
| LM                  | 32 hex chars                         | ✅        | 3000         |
| SHA‑1               | 40 hex chars                         | ✅        | 100          |
| SHA‑256 / SHA3‑256  | 64 hex chars                         | ✅        | 1400 / 17400 |
| SHA‑512 / SHA3‑512  | 128 hex chars                        | ✅        | 1700 / 17600 |
| SHA‑384 / SHA3‑384  | 96 hex chars                         | ✅        | 10800 / 17500|
| SHA‑224 / SHA3‑224  | 56 hex chars                         | ✅        | 1300 / 17300 |
| MySQL3.x            | 16 hex chars                         | ✅        | 200          |
| MySQL4/5            | 40 hex chars (SHA‑1)                 | ✅        | 300          |
| RIPEMD‑128/160/256  | 32 / 40 / 64 hex chars               | ❌/✅      | 6000         |
| bcrypt              | `$2a$...` / `$2y$...`                | ❌        | 3200         |
| scrypt              | `$7$...`                             | ❌        | 8900         |
| Argon2i / Argon2id  | `$argon2i$...` / `$argon2id$...`     | ❌        | –            |
| WordPress / phpass   | `$P$...`                             | ✅        | 400          |
| Cisco MD5 Crypt      | `$1$...`                             | ✅        | 500          |
| SHA‑512/256 Crypt    | `$6$...` / `$5$...`                  | ✅        | 1800 / 7400  |
| PBKDF2‑SHA256/512    | `pbkdf2_sha256$...`                  | ❌        | –            |
| Django SHA1/256      | `sha1$...` / `sha256$...`            | ✅        | –            |
| Joomla MD5           | `32hex:32hex`                        | ✅        | 11           |
| WPA‑PMKID            | `32hex*...*...`                      | ✅        | 22000        |

> ✅ Crackable = built‑in + system wordlist attack supported.  
> ❌ Not crackable by this tool (requires GPU or more specialised attacks).

---

## HIBP (Have I Been Pwned) Integration

When a password is cracked, the tool automatically queries the **Have I Been Pwned** API using the k‑anonymity model:
- It sends only the first 5 characters of the SHA‑1 hash.
- The API returns a list of matching hash suffixes and their breach counts.
- Your password **never leaves your machine** in plain text.

If the password is found, you'll see something like:
```
[HIBP] Found in 15,234,567 breach(es) — compromised!
```

---

## Wordlist Management

The tool automatically scans common system paths for wordlists:
- `/usr/share/wordlists`
- `/usr/share/dict`
- `/usr/share/seclists`
- `/opt/wordlists`

It prioritises `rockyou.txt` (uncompressed) if found. The built‑in list (~130 entries) is always tried first and is enough for most CTF passwords.

---

## Credits

- **Author:** rudreshark
- **Version:** 4.0
- **Inspired by:** CTF tools like CyberChef, hash‑identifier, and John the Ripper.

---

## Disclaimer

```
This tool is intended for authorized CTF competitions, penetration testing with explicit permission, 
and educational purposes only. 

Misuse of this tool to access systems without authorization is illegal and unethical. 
The author assumes no liability for any damage caused by its use.
```

---

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
```

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/264422d4-2972-4824-b61f-63e1960d6f95" />
<img width="1360" height="487" alt="image" src="https://github.com/user-attachments/assets/db2961ba-a6f6-44a8-995a-7c92b11eef9a" />
<img width="1353" height="767" alt="image" src="https://github.com/user-attachments/assets/04ed4a21-57b0-44cb-b645-4c0a3980b8ba" />
