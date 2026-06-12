#!/usr/bin/env python3
"""
HASHNAMER v4 – CTF Multi-Decoder, Hash Identifier & Cracker
Author  : rudreshark
Purpose : Authorized CTF / ethical hacking assessments only
"""
import re, sys, os, hashlib, base64, string, binascii, math
import subprocess, tempfile, shutil, urllib.parse, html
import urllib.request
from collections import Counter
from itertools import product

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    R=Fore.RED; G=Fore.GREEN; Y=Fore.YELLOW; C=Fore.CYAN
    M=Fore.MAGENTA; LG=Fore.LIGHTGREEN_EX; LB=Fore.LIGHTBLUE_EX
    RESET=Style.RESET_ALL; BRIGHT=Style.BRIGHT
except ImportError:
    class _C:
        def __getattr__(self,n): return ''
    Fore=Style=_C()
    R=G=Y=C=M=LG=LB=RESET=BRIGHT=''

BANNER = f"""
{R}  ██╗  ██╗ █████╗ ███████╗██╗  ██╗███╗   ██╗ █████╗ ███╗   ███╗███████╗██████╗ 
{R}  ██║  ██║██╔══██╗██╔════╝██║  ██║████╗  ██║██╔══██╗████╗ ████║██╔════╝██╔══██╗
{R}  ███████║███████║███████╗███████║██╔██╗ ██║███████║██╔████╔██║█████╗  ██████╔╝
{R}  ██╔══██║██╔══██║╚════██║██╔══██║██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗
{R}  ██║  ██║██║  ██║███████║██║  ██║██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
{R}  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
{Y}  ⚡────── v4 · 46 METHODS · HASH CRACKER · HIBP · AUTO-CHAIN ──────⚡
{LB}  [*] For authorized CTF / ethical hacking assessments only
"""

# ══════════════════════════════════════════════════════════════
#  HASH SIGNATURES
# ══════════════════════════════════════════════════════════════
HASH_SIGS = [
    ('CRC32',             r'^[a-f0-9]{8}$',                                  None,  None),
    ('Adler32',           r'^[a-f0-9]{8}$',                                  None,  None),
    ('MySQL3.x',          r'^[a-f0-9]{16}$',                                 200,   'mysql'),
    ('MD5',               r'^[a-f0-9]{32}$',                                 0,     'raw-md5'),
    ('MD4',               r'^[a-f0-9]{32}$',                                 900,   'raw-md4'),
    ('NTLM',              r'^[a-f0-9]{32}$',                                 1000,  'nt'),
    ('LM',                r'^[a-f0-9]{32}$',                                 3000,  'lm'),
    ('RIPEMD-128',        r'^[a-f0-9]{32}$',                                 None,  'ripemd-128'),
    ('Tiger-192',         r'^[a-f0-9]{48}$',                                 None,  None),
    ('SHA-1',             r'^[a-f0-9]{40}$',                                 100,   'raw-sha1'),
    ('MySQL4/5',          r'^[a-f0-9]{40}$',                                 300,   'mysql-sha1'),
    ('RIPEMD-160',        r'^[a-f0-9]{40}$',                                 6000,  'ripemd-160'),
    ('SHA-224',           r'^[a-f0-9]{56}$',                                 1300,  'raw-sha224'),
    ('SHA3-224',          r'^[a-f0-9]{56}$',                                 17300, None),
    ('SHA-256',           r'^[a-f0-9]{64}$',                                 1400,  'raw-sha256'),
    ('SHA3-256',          r'^[a-f0-9]{64}$',                                 17400, None),
    ('RIPEMD-256',        r'^[a-f0-9]{64}$',                                 None,  None),
    ('BLAKE2s-256',       r'^[a-f0-9]{64}$',                                 None,  None),
    ('SHA-384',           r'^[a-f0-9]{96}$',                                 10800, 'raw-sha384'),
    ('SHA3-384',          r'^[a-f0-9]{96}$',                                 17500, None),
    ('SHA-512',           r'^[a-f0-9]{128}$',                                1700,  'raw-sha512'),
    ('SHA3-512',          r'^[a-f0-9]{128}$',                                17600, None),
    ('Whirlpool',         r'^[a-f0-9]{128}$',                                6100,  'whirlpool'),
    ('BLAKE2b-512',       r'^[a-f0-9]{128}$',                                None,  None),
    ('bcrypt',            r'^\$2[aby]\$\d{2}\$.{53}$',                       3200,  'bcrypt'),
    ('scrypt',            r'^\$7\$[A-Za-z0-9./]{1,11}\$.+$',                 8900,  None),
    ('Argon2i',           r'^\$argon2i\$.+$',                                None,  None),
    ('Argon2id',          r'^\$argon2id\$.+$',                               None,  None),
    ('Django SHA1',       r'^sha1\$.+\$.+$',                                 None,  'django-sha1'),
    ('Django SHA256',     r'^sha256\$.+\$.+$',                               None,  'django-sha256'),
    ('WordPress/phpass',  r'^\$P\$[./0-9A-Za-z]{31}$',                      400,   'phpass'),
    ('Joomla MD5',        r'^[a-f0-9]{32}:[a-zA-Z0-9]{32}$',                11,    None),
    ('WPA-PMKID',         r'^[a-f0-9]{32}\*[a-f0-9]+\*[a-f0-9]+\*[a-f0-9]+$', 22000, None),
    ('Cisco MD5 Crypt',   r'^\$1\$.+\$.+$',                                  500,   'md5crypt'),
    ('SHA-512 Crypt',     r'^\$6\$.+\$.+$',                                  1800,  'sha512crypt'),
    ('SHA-256 Crypt',     r'^\$5\$.+\$.+$',                                  7400,  'sha256crypt'),
    ('PBKDF2-SHA256',     r'^pbkdf2_sha256\$.+\$.+\$.+$',                    None,  'pbkdf2-hmac-sha256'),
    ('PBKDF2-SHA512',     r'^pbkdf2_sha512\$.+\$.+\$.+$',                    None,  'pbkdf2-hmac-sha512'),
]

# ══════════════════════════════════════════════════════════════
#  BUILT-IN WORDLIST
# ══════════════════════════════════════════════════════════════
BUILTIN_WORDLIST = [
    "123456","password","123456789","12345678","12345","1234567","qwerty",
    "abc123","password1","iloveyou","admin","letmein","monkey","dragon",
    "111111","baseball","master","sunshine","passw0rd","shadow","123123",
    "654321","superman","michael","football","password123","welcome","hello",
    "charlie","donald","pass","test","guest","root","toor","alpine",
    "raspberry","changeme","default","admin123","pass123","P@ssw0rd",
    "P@$$w0rd","Winter2024","Summer2024","Winter2025","Summer2025",
    "Winter2026","Summer2026","Company@123","Company@2025","Welcome2025",
    "Passw0rd!","1q2w3e4r","1q2w3e","zxcvbnm","asdfghjkl","qwertyuiop",
    "11111111","00000000","12341234","123321","666666","999999","696969",
    "mypassword","testing","test123","qwerty1","football1","soccer","hockey",
    "batman","spiderman","ironman","matrix","starwars","minecraft","fortnite",
    "pokemon","pikachu","naruto","dragon123","tiger","secret","secret123",
    "trustno1","hacker","kali","kalilinux","metasploit","nmap","sqlmap",
    "burpsuite","pentest","exploit","ctf2024","ctf2025","ctf2026","flag123",
    "hackthebox","tryhackme","picoctf","overthewire","cybersecurity","infosec",
    "admin@123","root@123","ubuntu","debian","fedora","windows","windows11",
    "microsoft","google123","facebook","instagram","twitter","amazon","netflix",
    "iloveyou1","baby123","sunshine1","rainbow","princess","letmein1",
]

# ══════════════════════════════════════════════════════════════
#  ENGLISH SCORING
# ══════════════════════════════════════════════════════════════
ENGLISH_FREQ = 'etaoinshrdlucmfywgpbvkxqjz'
COMMON_WORDS = ['the ','and ','flag{','ctf{','is ','in ','of ','to ',
                ' you ','this ','are ','was ','for ','have ','it ',
                ' with ',' he ',' she ',' they ',' we ',' at ','be ',
                ' from ','or ','an ','but ','not ','what ','all ',
                'were ','when ','your ','key{','pass{']

def english_score(s):
    s_low = s.lower()
    freq_score = sum(26 - ENGLISH_FREQ.index(c) for c in s_low if c in ENGLISH_FREQ)
    word_score  = sum(100 for w in COMMON_WORDS if w in s_low)
    flag_score  = 500 if any(p in s_low for p in ['flag{','ctf{','key{','pass{']) else 0
    return freq_score + word_score + flag_score

def is_meaningful(s):
    if not s or not s.strip(): return False
    s = s.strip()
    if len(s) < 2: return False
    bad = sum(1 for c in s if c not in string.printable or ord(c) < 9)
    if bad / len(s) > 0.05: return False
    special = sum(1 for c in s if c in '}{][|\\^`~')
    if len(s) > 4 and special / len(s) > 0.45: return False
    return True

PLAIN_CHARS = set(string.ascii_letters + string.digits + ' .,!?-_{}[]():;\'"@#/')
def is_plaintext(s):
    if not s or len(s) < 2: return False
    plain = sum(1 for c in s if c in PLAIN_CHARS)
    return plain / len(s) > 0.82

# ══════════════════════════════════════════════════════════════
#  CONFIDENCE BAR
# ══════════════════════════════════════════════════════════════
def conf_bar(score):
    filled = int(score / 10)
    bar = chr(9608)*filled + chr(9617)*(10-filled)
    color = G if score >= 80 else Y if score >= 60 else R
    return f"{color}[{bar}] {score}%{RESET}"

# ══════════════════════════════════════════════════════════════
#  ALL DECODER FUNCTIONS
# ══════════════════════════════════════════════════════════════
def clean_null(s):
    return s.replace('\x00','').replace('^@','')

def from_rot13(s):
    return s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))

def from_rot47(s):
    return ''.join(chr(33+((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in s)

def from_atbash(s):
    return s.translate(str.maketrans(
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'))

def caesar_brute(s):
    best_score, best_shift, best_text = -1, None, None
    for shift in range(1, 26):
        out = []
        for c in s:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c)-base+shift)%26+base))
            else:
                out.append(c)
        candidate = ''.join(out)
        score = english_score(candidate)
        if score > best_score:
            best_score, best_shift, best_text = score, shift, candidate
    return (best_shift, best_text) if best_score > 0 else (None, None)

def affine_brute(s):
    valid_a = [a for a in range(1,26) if math.gcd(a,26)==1]
    results = []
    for a in valid_a:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            out = []
            for c in s:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    p = (a_inv * (ord(c)-base - b)) % 26
                    out.append(chr(p + base))
                else:
                    out.append(c)
            candidate = ''.join(out)
            score = english_score(candidate)
            results.append((score, a, b, candidate))
    results.sort(reverse=True)
    return results[:3]

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c)-base-shift)%26+base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

def vigenere_brute(s):
    common_keys = ['key','flag','ctf','secret','password','abc','admin',
                   'hack','crypto','cipher','test','hello','kali','pass',
                   'leet','root','user','code','game','dark','red','blue',
                   'cyber','shell','linux','python','java','ruby','rust']
    results = []
    letters = ''.join(c for c in s if c.isalpha())
    if not letters: return []

    for k in common_keys:
        dec = vigenere_decrypt(s, k)
        score = english_score(dec)
        if score > 0:
            results.append((score, f'key="{k}"', dec))

    for k in product(string.ascii_lowercase, repeat=2):
        key = ''.join(k)
        dec = vigenere_decrypt(s, key)
        score = english_score(dec)
        if score > 20:
            results.append((score, f'key="{key}"', dec))

    results.sort(reverse=True)
    return results[:5]

def rail_fence_decrypt(s, rails):
    n = len(s)
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0: direction = 1
        elif rail == rails-1: direction = -1
        rail += direction
    indices = sorted(range(n), key=lambda x: (pattern[x], x))
    result = [''] * n
    for i, ch in zip(indices, s):
        result[i] = ch
    return ''.join(result)

def rail_fence_brute(s):
    results = []
    for r in range(2, min(len(s)//2+1, 8)):
        dec = rail_fence_decrypt(s, r)
        score = english_score(dec)
        results.append((score, r, dec))
    results.sort(reverse=True)
    return results[:3]

def polybius_decode(s):
    tokens = re.findall(r'[1-5]{2}', re.sub(r'\s', '', s))
    if not tokens or len(tokens) < 2: return ''
    TABLE = {
        '11':'a','12':'b','13':'c','14':'d','15':'e',
        '21':'f','22':'g','23':'h','24':'i','25':'k',
        '31':'l','32':'m','33':'n','34':'o','35':'p',
        '41':'q','42':'r','43':'s','44':'t','45':'u',
        '51':'v','52':'w','53':'x','54':'y','55':'z'
    }
    res = ''.join(TABLE.get(t,'?') for t in tokens)
    return res if '?' not in res else ''

def a1z26_decode(s):
    tokens = re.split(r'[\s\-,]+', s.strip())
    if not tokens or len(tokens) < 2: return ''
    try:
        vals = [int(t) for t in tokens if t]
        if all(1 <= v <= 26 for v in vals):
            return ''.join(chr(v + ord('a') - 1) for v in vals)
    except: pass
    return ''

def nato_decode(s):
    NATO = {
        'alpha':'a','bravo':'b','charlie':'c','delta':'d','echo':'e',
        'foxtrot':'f','golf':'g','hotel':'h','india':'i','juliet':'j',
        'kilo':'k','lima':'l','mike':'m','november':'n','oscar':'o',
        'papa':'p','quebec':'q','romeo':'r','sierra':'s','tango':'t',
        'uniform':'u','victor':'v','whiskey':'w','xray':'x','x-ray':'x',
        'yankee':'y','zulu':'z',
        'zero':'0','one':'1','two':'2','three':'3','four':'4',
        'five':'5','six':'6','seven':'7','eight':'8','nine':'9'
    }
    words = re.split(r'[\s,\-]+', s.lower())
    result = []
    for w in words:
        w = w.strip()
        if w in NATO:
            result.append(NATO[w])
        elif w:
            return ''
    return ''.join(result) if len(result) >= 3 else ''

def t9_decode(s):
    T9 = {
        '2':'a','22':'b','222':'c',
        '3':'d','33':'e','333':'f',
        '4':'g','44':'h','444':'i',
        '5':'j','55':'k','555':'l',
        '6':'m','66':'n','666':'o',
        '7':'p','77':'q','777':'r','7777':'s',
        '8':'t','88':'u','888':'v',
        '9':'w','99':'x','999':'y','9999':'z',
        '0':' ','00':'.'
    }
    tokens = s.strip().split()
    if len(tokens) < 2: return ''
    if not all(re.match(r'^[2-90]+$', t) for t in tokens): return ''
    res = ''.join(T9.get(t,'?') for t in tokens)
    return res if '?' not in res else ''

def leet_normalize(s):
    TABLE = str.maketrans('013456789@$!|+', 'oieasgbzagsia!')
    result = s.translate(TABLE)
    return result if result != s else ''

def reverse_string(s):
    return s[::-1]

def unicode_escape_decode(s):
    try:
        result = s.encode('raw_unicode_escape').decode('unicode_escape')
        return result if result != s else ''
    except:
        try:
            result = bytes(s, 'utf-8').decode('unicode_escape')
            return result if result != s else ''
        except: return ''

def jwt_decode(s):
    parts = s.split('.')
    if len(parts) != 3: return ''
    try:
        header_b64  = parts[0] + '=' * (-len(parts[0]) % 4)
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        header  = base64.urlsafe_b64decode(header_b64).decode('utf-8', errors='ignore')
        payload = base64.urlsafe_b64decode(payload_b64).decode('utf-8', errors='ignore')
        return f"[JWT]\nHeader  : {header}\nPayload : {payload}"
    except: return ''

# ── Base encodings ───────────────────────────────────────────
def decode_base16(s):
    try: return bytes.fromhex(s).decode('utf-8', errors='ignore')
    except: return ''

def decode_base32(s):
    try:
        stripped = s.rstrip('=')
        padding = (8 - len(stripped) % 8) % 8
        return base64.b32decode(stripped.upper() + '='*padding).decode('utf-8', errors='ignore')
    except: return ''

def decode_base36(s):
    try:
        n = int(s, 36)
        res = bytearray()
        while n > 0:
            n, mod = divmod(n, 256)
            res.append(mod)
        return res[::-1].decode('utf-8', errors='ignore')
    except: return ''

def decode_base45(s):
    CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:'
    try:
        n = 0
        for c in s:
            if c not in CHARSET: return ''
            n = n * 45 + CHARSET.index(c)
        res = bytearray()
        while n > 0:
            n, mod = divmod(n, 256)
            res.append(mod)
        return res[::-1].decode('utf-8', errors='ignore')
    except: return ''

def decode_base58(s):
    B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if not all(c in B58 for c in s): return ''
    num = 0
    for c in s: num = num*58 + B58.index(c)
    res = bytearray()
    while num > 0:
        num, mod = divmod(num, 256)
        res.append(mod)
    return res[::-1].decode('utf-8', errors='ignore')

def decode_base62(s):
    B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
    if not all(c in B62 for c in s): return ''
    num = 0
    for c in s: num = num*62 + B62.index(c)
    res = bytearray()
    while num > 0:
        num, mod = divmod(num, 256)
        res.append(mod)
    return res[::-1].decode('utf-8', errors='ignore')

def decode_base64(s):
    try:
        pad = s + '=' * (-len(s) % 4)
        r = base64.b64decode(pad).decode('utf-8', errors='ignore')
        return r if r.strip() else ''
    except: return ''

def decode_base64_url(s):
    try:
        s2 = s.replace('-','+').replace('_','/')
        pad = s2 + '=' * (-len(s2) % 4)
        r = base64.b64decode(pad).decode('utf-8', errors='ignore')
        return r if r.strip() else ''
    except: return ''

def decode_base85(s):
    try: return base64.b85decode(s.encode()).decode('utf-8', errors='ignore')
    except: pass
    try: return base64.a85decode(s.encode(), adobe=False).decode('utf-8', errors='ignore')
    except: pass
    try: return base64.a85decode(s.encode(), adobe=True).decode('utf-8', errors='ignore')
    except: return ''

def decode_base91(s):
    B91='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    v,b,n=-1,0,0
    out=bytearray()
    for c in s:
        if c not in B91: continue
        p=B91.index(c)
        if v<0: v=p
        else:
            v+=p*91; b|=v<<n
            n+=13 if (v&8191)>88 else 14
            while True:
                out.append(b&255); b>>=8; n-=8
                if n<8: break
            v=-1
    if v>=0: out.append((b|v<<n)&255)
    return out.decode('utf-8', errors='ignore')

def from_hex_str(s):
    try: return bytes.fromhex(s.replace(' ','')).decode('utf-8', errors='ignore')
    except: return ''

def from_binary(s):
    clean = re.sub(r'[^01\s]','',s).strip()
    tokens = clean.split() if ' ' in clean else [clean[i:i+8] for i in range(0,len(clean),8)]
    try: return bytes(int(t[:8],2) for t in tokens if len(t)>=8).decode('utf-8', errors='ignore')
    except: return ''

def from_octal(s):
    tokens = re.findall(r'[0-7]+',s)
    if not tokens: return ''
    try: return ''.join(chr(int(t,8)) for t in tokens if int(t,8)<0x110000)
    except: return ''

def from_decimal(s):
    tokens = re.findall(r'\d+',s)
    if len(tokens) < 2: return ''
    vals = [int(t) for t in tokens]
    if any(v>255 for v in vals): return ''
    try: return bytes(vals).decode('utf-8', errors='ignore')
    except: return ''

def from_url(s):
    try:
        d = urllib.parse.unquote(s)
        return d if d != s else ''
    except: return ''

def from_html_entities(s):
    try:
        d = html.unescape(s)
        return d if d != s else ''
    except: return ''

def from_morse(s):
    TABLE = {
        '.-':'a','-...':'b','-.-.':'c','-..':'d','.':'e','..-.':'f',
        '--.':'g','....':'h','..':'i','.---':'j','-.-':'k','.-..':'l',
        '--':'m','-.':'n','---':'o','.--.':'p','--.-':'q','.-.':'r',
        '...':'s','-':'t','..-':'u','...-':'v','.--':'w','-..-':'x',
        '-.--':'y','--..':'z','.----':'1','..---':'2','...--':'3',
        '....-':'4','.....':'5','-....':'6','--...':'7','---..':'8',
        '----.':'9','-----':'0','/':' '
    }
    tokens = re.split(r'\s+', s.strip())
    res = ''.join(TABLE.get(t,'?') for t in tokens if t)
    return res if '?' not in res else ''

def from_bacon(s):
    s2 = re.sub(r'[^ABab\s]','',s).upper().strip()
    tokens = s2.split()
    if not tokens or any(len(t)!=5 for t in tokens): return ''
    TABLE = {
        'AAAAA':'a','AAAAB':'b','AAABA':'c','AAABB':'d','AABAA':'e',
        'AABAB':'f','AABBA':'g','AABBB':'h','ABAAA':'i','ABAAB':'j',
        'ABABA':'k','ABABB':'l','ABBAA':'m','ABBAB':'n','ABBBA':'o',
        'ABBBB':'p','BAAAA':'q','BAAAB':'r','BAABA':'s','BAABB':'t',
        'BABAA':'u','BABAB':'v','BABBA':'w','BABBB':'x','BBAAA':'y','BBAAB':'z'
    }
    res = ''.join(TABLE.get(t,'?') for t in tokens)
    return res if '?' not in res else ''

def from_quoted_printable(s):
    try:
        import quopri
        r = quopri.decodestring(s.encode()).decode('utf-8', errors='ignore')
        return r if r != s else ''
    except: return ''

def from_scientific_notation(s):
    tokens = re.findall(r'\d+\.?\d*[eE][+\-]?\d+', s)
    if not tokens: return ''
    out = []
    for t in tokens:
        try:
            v = int(float(t))
            h = hex(v)[2:]
            if len(h)%2: h='0'+h
            out.append(bytes.fromhex(h).decode('utf-8', errors='ignore'))
        except: pass
    return ''.join(out)

def xor_brute(s):
    try:
        raw = bytes.fromhex(s.replace(' ','')) if re.match(r'^[a-fA-F0-9\s]+$',s) else s.encode('latin-1')
    except: return []
    results = []
    for key in range(1, 256):
        out = bytes(b^key for b in raw)
        try:
            decoded = out.decode('utf-8', errors='ignore')
            score = english_score(decoded)
            ratio = sum(1 for b in out if 32<=b<127) / len(out)
            if score > 0 or ratio > 0.95:
                results.append((score+ratio, key, decoded))
        except: pass
    results.sort(reverse=True)
    return results[:5]

def strip_hexdump_offsets(s):
    lines = s.strip().splitlines()
    cleaned = []
    for line in lines:
        line = re.sub(r'^\s*(?:0x)?[0-9a-fA-F]{4,8}:\s*','',line)
        if '|' in line: line = line.split('|')[0]
        cleaned.append(line.strip())
    joined = ' '.join(cleaned).strip()
    return joined if re.match(r'^[a-fA-F0-9\s]+$', joined) else s.strip()

# ══════════════════════════════════════════════════════════════
#  OPERATION TABLE
# ══════════════════════════════════════════════════════════════
OPS = [
    ('JWT Token',          re.compile(r'^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$'), jwt_decode,            98),
    ('Unicode Escape',     re.compile(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}'),                 unicode_escape_decode,  95),
    ('Quoted-Printable',   re.compile(r'(?:=[0-9A-F]{2}){2,}'),                                  from_quoted_printable,  90),
    ('HTML Entities',      re.compile(r'&(?:#\d+|#x[0-9a-fA-F]+|[a-z]+);'),                     from_html_entities,     92),
    ('URL Percent-Encode', re.compile(r'(?:%[0-9a-fA-F]{2}){2,}'),                              from_url,               92),
    ('Scientific Notation',re.compile(r'^(?:\s*\d+\.?\d*[eE][+\-]?\d+\s*)+$', re.I),           from_scientific_notation, 85),
    ('Polybius Square',    re.compile(r'^(?:[1-5]{2}[\s,]*){3,}$'),                              polybius_decode,        88),
    ('A1Z26 Numbers',      re.compile(r'^(?:[1-9]|1[0-9]|2[0-6])(?:[\s\-,]+(?:[1-9]|1[0-9]|2[0-6])){2,}$'), a1z26_decode, 85),
    ('T9 Keypad',          re.compile(r'^(?:[2-9]+\s+){2,}[2-9]+$'),                            t9_decode,              82),
    ('Morse Code',         re.compile(r'^[.\-\s/]{4,}$'),                                        from_morse,             90),
    ('Bacon Cipher',       re.compile(r'^(?:[ABab]{5}\s*)+$'),                                   from_bacon,             95),
    ('Binary',             re.compile(r'^[01\s]{8,}$'),                                          from_binary,            85),
    ('Octal',              re.compile(r'^(?:[0-7]{1,3}\s+){2,}[0-7]{1,3}$'),                    from_octal,             85),
    ('Decimal',            re.compile(r'^(?:\d{1,3}\s+){2,}\d{1,3}$'),                          from_decimal,           82),
    ('Hex Spaced',         re.compile(r'^(?:[a-fA-F0-9]{2}\s)+[a-fA-F0-9]{2}$'),                from_hex_str,           90),
    ('Hex Raw',            re.compile(r'^[a-fA-F0-9]{10,}$'),                                   from_hex_str,           80),
    ('Base32',             re.compile(r'^[A-Z2-7]+=*$'),                                         decode_base32,          83),
    ('Base64 URL-safe',    re.compile(r'^[A-Za-z0-9\-_]+=*$'),                                  decode_base64_url,      80),
    ('Base64 Standard',    re.compile(r'^[A-Za-z0-9+/]+=*$'),                                   decode_base64,          80),
    ('Base58',             re.compile(r'^[1-9A-HJ-NP-Za-km-z]{4,}$'),                           decode_base58,          75),
    ('Base62',             re.compile(r'^[0-9A-Za-z]{8,}$'),                                    decode_base62,          70),
    ('Base85/Ascii85',     re.compile(r'^[\x21-\x75]{5,}$'),                                    decode_base85,          78),
    ('Base91',             re.compile(r'^[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~"]{4,}$'),   decode_base91,          72),
    ('ROT47',              re.compile(r'^[\x21-\x7e]{4,}$'),                                    from_rot47,             65),
    ('NATO Phonetic',      re.compile(r'^(?:alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliet|kilo|lima|mike|november|oscar|papa|quebec|romeo|sierra|tango|uniform|victor|whiskey|x-?ray|yankee|zulu)(?:[\s,\-]+(?:alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliet|kilo|lima|mike|november|oscar|papa|quebec|romeo|sierra|tango|uniform|victor|whiskey|x-?ray|yankee|zulu))+$', re.I), nato_decode, 95),
]

# ══════════════════════════════════════════════════════════════
#  HASH IDENTIFIER
# ══════════════════════════════════════════════════════════════
def identify_hashes(s):
    return [(name, hc, jf) for name, pat, hc, jf in HASH_SIGS
            if re.match(pat, s.strip(), re.IGNORECASE)]

def pick_hash_type(s, matches):
    # Automatic: pick the first match (prioritises MD5 over NTLM for 32‑hex, etc.)
    return matches[0]

# ══════════════════════════════════════════════════════════════
#  HIBP CHECKER
# ══════════════════════════════════════════════════════════════
def check_hibp(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        req = urllib.request.Request(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'hashnamer-v4-ctf'})
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = resp.read().decode()
        for line in body.splitlines():
            parts = line.strip().split(':')
            if len(parts)==2 and parts[0]==suffix: return int(parts[1])
        return 0
    except: return -1

# ══════════════════════════════════════════════════════════════
#  SYSTEM WORDLIST MANAGER
# ══════════════════════════════════════════════════════════════
class WordlistManager:
    DIRS    = ['/usr/share/wordlists','/opt/wordlists',
               '/usr/share/dict','/usr/share/seclists']
    TARGETS = {'rockyou.txt','rockyou.txt.gz','fasttrack.txt',
               'common.txt','words','probable-v2-top12000.txt'}
    def __init__(self):
        self.found=[]
        self._scan()
    def _scan(self):
        for d in self.DIRS:
            if not os.path.isdir(d): continue
            for root,_,files in os.walk(d):
                for f in files:
                    if f in self.TARGETS or 'password' in f.lower():
                        self.found.append(os.path.join(root,f))
        self.found=list(set(self.found))
    def best(self):
        for p in self.found:
            if 'rockyou' in p.lower() and not p.endswith('.gz'): return p
        for p in self.found:
            if 'rockyou' in p.lower(): return p
        return self.found[0] if self.found else None
    def summary(self):
        if not self.found: return f"{R}None found{RESET}"
        return f"{G}{len(self.found)} list(s){RESET} — best: {os.path.basename(self.best())}"

# ══════════════════════════════════════════════════════════════
#  CRACK FUNCTIONS
# ══════════════════════════════════════════════════════════════
ALGO_MAP = {
    'MD5':'md5','SHA-1':'sha1','SHA-224':'sha224','SHA-256':'sha256',
    'SHA-384':'sha384','SHA-512':'sha512','SHA3-256':'sha3_256',
    'SHA3-512':'sha3_512','SHA3-224':'sha3_224','SHA3-384':'sha3_384',
}
def _get_algo(name):
    for k,v in ALGO_MAP.items():
        if k in name: return v
    return None

def crack_builtin(hash_str, hash_name):
    algo = _get_algo(hash_name)
    if not algo: return None
    for word in BUILTIN_WORDLIST:
        try:
            if hashlib.new(algo, word.encode()).hexdigest().lower()==hash_str.lower(): return word
        except: continue
    return None

def crack_file_wordlist(hash_str, hash_name, wl_path):
    algo = _get_algo(hash_name)
    if not algo: return None
    count = 0
    try:
        import gzip as gz
        opener = gz.open if wl_path.endswith('.gz') else open
        with opener(wl_path,'rt',encoding='utf-8',errors='ignore') as f:
            for line in f:
                w = line.strip()
                if not w: continue
                try:
                    if hashlib.new(algo,w.encode()).hexdigest().lower()==hash_str.lower(): return w
                except: continue
                count+=1
                if count%200000==0: print(f"  {C}[*] Tried {count:,} passwords...{RESET}",end='\r')
    except Exception as e: print(f"\n  {R}[!] Wordlist error: {e}{RESET}")
    return None

def auto_crack(hash_str, hash_name, wl_mgr):
    """
    Fully automatic cracking:
    1. Built‑in wordlist
    2. System wordlist (if available)
    Returns plaintext or None
    """
    # 1. Built‑in
    print(f"  {C}[*] Trying built‑in wordlist...{RESET}")
    cracked = crack_builtin(hash_str, hash_name)
    if cracked:
        print(f"  {G}[+] Cracked with built‑in!{RESET}")
        return cracked

    # 2. System wordlist
    wl = wl_mgr.best()
    if wl:
        print(f"  {C}[*] Trying system wordlist {os.path.basename(wl)}...{RESET}")
        cracked = crack_file_wordlist(hash_str, hash_name, wl)
        if cracked:
            print(f"\n  {G}[+] Cracked with system wordlist!{RESET}")
            return cracked
        else:
            print(f"\n  {R}[!] Not found in system wordlist.{RESET}")
    else:
        print(f"  {Y}[!] No system wordlist available.{RESET}")
    return None

# ══════════════════════════════════════════════════════════════
#  MAIN PIPELINE ENGINE
# ══════════════════════════════════════════════════════════════
class Hashnamer:
    def __init__(self):
        self.wl = WordlistManager()

    def _print_step(self, step, method, result, conf=None):
        conf_str = f"  {conf_bar(conf)}" if conf else ''
        print(f"\n  {G}[STEP {step}] Method  : {Y}{method}{RESET}{conf_str}")
        print(f"  {G}         Result  : {BRIGHT}{str(result)[:300]}{RESET}")

    def _final(self, current, div):
        print(f"\n{div}")
        print(f"  {LG}[FINAL DECODED OUTPUT]")
        print(f"  {BRIGHT}{current}{RESET}")
        print(div)

    def process(self, data):
        step = 0
        current = strip_hexdump_offsets(data.strip())
        seen = {current}
        div = f"  {LB}{'─'*62}{RESET}"

        print(f"\n{div}")
        print(f"  {C}INPUT : {RESET}{current[:120]}{'...' if len(current)>120 else ''}")
        print(div)

        while True:
            if not current: break

            # ── 1. Short hex → try decode first before hash ID ────
            if re.match(r'^[a-fA-F0-9]{6,32}$', current) and len(current) % 2 == 0:
                try:
                    decoded_hex = bytes.fromhex(current).decode('utf-8')
                    if decoded_hex.isprintable() and len(decoded_hex) >= 2:
                        step += 1
                        self._print_step(step, 'Hex Raw', decoded_hex, 88)
                        current = clean_null(decoded_hex)
                        seen.add(current)
                        continue
                except: pass

            # ── 2. Hash identification ────────────────────────────
            matches = identify_hashes(current)
            if matches:
                hash_name, hc_mode, john_fmt = pick_hash_type(current, matches)
                print(f"\n  {G}╔══ HASH IDENTIFIED ══╗{RESET}")
                print(f"  {Y}  Type    : {RESET}{hash_name}")
                print(f"  {Y}  Value   : {RESET}{current}")
                if hc_mode is not None:
                    print(f"  {Y}  Hashcat : {RESET}-m {hc_mode}")
                if john_fmt:
                    print(f"  {Y}  John    : {RESET}--format={john_fmt}")

                crackable=['MD5','SHA-1','SHA-256','SHA-512','SHA-384',
                           'NTLM','LM','MD4','MySQL','SHA3']
                if any(t in hash_name for t in crackable):
                    # Auto‑crack without asking
                    print(f"  {C}[*] Attempting automatic cracking...{RESET}")
                    cracked = auto_crack(current, hash_name, self.wl)
                    if cracked:
                        print(f"\n  {G}{'═'*52}")
                        print(f"  {G}  CRACKED  ->  {BRIGHT}{cracked}{RESET}")
                        print(f"  {G}{'═'*52}")
                        # Check HIBP for the cracked password
                        print(f"\n  {C}[*] Checking HIBP breach database...{RESET}")
                        count = check_hibp(cracked)
                        if count > 0:
                            print(f"  {R}[HIBP]  Found in {count:,} breach(es) — compromised!{RESET}")
                        elif count == 0:
                            print(f"  {G}[HIBP]  Not found in known breaches.{RESET}")
                        else:
                            print(f"  {Y}[HIBP]  API unreachable (offline/timeout).{RESET}")
                        current = cracked
                        seen.add(current)
                        step += 1
                        continue
                    else:
                        print(f"\n  {R}[!] Could not crack with available resources.{RESET}")
                else:
                    print(f"  {Y}[*] {hash_name} cannot be cracked with standard wordlists.{RESET}")
                self._final(current, div)
                break

            # ── 3. Stop if already plaintext ─────────────────────
            if step > 0 and is_plaintext(current):
                self._final(current, div)
                break

            # ── 4. Early ROT13 check ─────────────────────────────
            _alpha_ratio = sum(1 for c in current if c.isalpha()) / max(len(current), 1)
            _is_alpha_text = _alpha_ratio > 0.70 and not re.match(r'^[A-Za-z0-9+/=]{8,}$', current)
            if _is_alpha_text:
                rot13_early = from_rot13(current)
                if rot13_early != current and is_meaningful(rot13_early):
                    if english_score(rot13_early) > english_score(current) + 50:
                        step += 1
                        self._print_step(step, 'ROT13', rot13_early, 85)
                        current = rot13_early
                        seen.add(current)
                        continue

            # ── 4b. Early Leet check ──────────────────────────────
            _leet_candidate = re.match(r'^[a-zA-Z0-9!@\$\{\}\[\]\(\)_\-\.]+$', current)
            if _leet_candidate and any(c in current for c in '013456789@$!'):
                leet_early = leet_normalize(current)
                if leet_early and leet_early != current and is_meaningful(leet_early):
                    if english_score(leet_early) > english_score(current) + 50:
                        step += 1
                        self._print_step(step, 'Leetspeak', leet_early, 78)
                        current = leet_early
                        seen.add(current)
                        continue

            # ── 5. Standard encoding/cipher ops ──────────────────
            decoded_flag = False
            for op_name, regex, func, conf in OPS:
                if regex.search(current):
                    try:
                        decoded = func(current)
                        if (decoded and decoded.strip() and decoded != current
                                and decoded not in seen and is_meaningful(decoded)):
                            step += 1
                            self._print_step(step, op_name, decoded.strip(), conf)
                            current = clean_null(decoded.strip())
                            seen.add(current)
                            decoded_flag = True
                            break
                    except: pass
            if decoded_flag: continue

            # ── 6. ROT13 fallback ─────────────────────────────────
            rot13 = from_rot13(current)
            if rot13 != current and is_meaningful(rot13):
                if english_score(rot13) > english_score(current):
                    step+=1; self._print_step(step,'ROT13',rot13,85)
                    current=rot13; seen.add(current); continue

            # ── 7. Atbash fallback ────────────────────────────────
            atbash = from_atbash(current)
            if atbash != current and is_meaningful(atbash):
                if any(t in atbash.lower() for t in ['flag{','ctf{','the ','and ']):
                    step+=1; self._print_step(step,'Atbash',atbash,80)
                    current=atbash; seen.add(current); continue

            # ── 8. Reverse string check ───────────────────────────
            rev = reverse_string(current)
            if rev != current and is_meaningful(rev) and english_score(rev) > english_score(current)+20:
                step+=1; self._print_step(step,'Reversed String',rev,70)
                current=rev; seen.add(current); continue

            # ── 9. Leet speak normalizer ──────────────────────────
            leet = leet_normalize(current)
            if leet and leet != current and is_meaningful(leet):
                if any(t in leet.lower() for t in ['flag','ctf','pass','admin','hack']):
                    step+=1; self._print_step(step,'Leetspeak',leet,75)
                    current=leet; seen.add(current); continue

            # ── 10. Caesar brute-force ─────────────────────────────
            if re.match(r'^[A-Za-z\s.,!?{}()\[\]_\-]+$', current) and len(current) > 3:
                shift, result = caesar_brute(current)
                if result and english_score(result) > english_score(current):
                    step+=1; self._print_step(step,f'Caesar Cipher (shift={shift})',result,75)
                    current=result; seen.add(current); continue

            # ── 11. Affine cipher brute-force ──────────────────────
            if re.match(r'^[A-Za-z\s.,!?]+$', current) and len(current) > 4:
                af_results = affine_brute(current)
                if af_results and af_results[0][0] > 30:
                    sc, a, b, dec = af_results[0]
                    if dec not in seen and is_meaningful(dec):
                        step+=1; self._print_step(step,f'Affine Cipher (a={a},b={b})',dec,72)
                        current=dec; seen.add(current); continue

            # ── 12. Rail fence brute-force ────────────────────────
            if len(current) > 6:
                rf_results = rail_fence_brute(current)
                if rf_results and rf_results[0][0] > 30:
                    sc, rails, dec = rf_results[0]
                    if dec not in seen and is_meaningful(dec) and dec != current:
                        step+=1; self._print_step(step,f'Rail Fence (rails={rails})',dec,70)
                        current=dec; seen.add(current); continue

            # ── 13. Vigenere brute-force ──────────────────────────
            if re.match(r'^[A-Za-z0-9\s\-_.,!?{}]+$', current) and len(current) > 5:
                vig_results = vigenere_brute(current)
                if vig_results and vig_results[0][0] > 30:
                    sc, key_str, dec = vig_results[0]
                    if dec not in seen and is_meaningful(dec):
                        want = input(f"\n  {Y}[?] Possible Vigenere ({key_str}) → {dec[:60]}\n      Apply? (Y/n): {RESET}").strip().lower()
                        if want != 'n':
                            step+=1; self._print_step(step,f'Vigenere Cipher ({key_str})',dec,68)
                            current=dec; seen.add(current); continue

            # ── 14. XOR brute-force offer ─────────────────────────
            xor_results = xor_brute(current)
            if xor_results and xor_results[0][0] > 1.5:
                print(f"\n  {Y}[XOR] Single-byte XOR candidates:{RESET}")
                for sc, key, text in xor_results:
                    safe = ''.join(c if 32<=ord(c)<127 else '.' for c in text)
                    print(f"    {C}key=0x{key:02X}{RESET}  ->  {safe[:80]}")
                choice = input(f"\n  {Y}[?] Apply XOR key? (e.g. 0x2f or N): {RESET}").strip().lower()
                if choice not in ('n','') and choice.startswith('0x'):
                    try:
                        xkey = int(choice, 16)
                        raw = (bytes.fromhex(current.replace(' ',''))
                               if re.match(r'^[a-fA-F0-9\s]+$', current)
                               else current.encode('latin-1'))
                        xored = bytes(b^xkey for b in raw).decode('utf-8',errors='ignore')
                        if xored and xored not in seen:
                            step+=1; self._print_step(step,f'XOR (key=0x{xkey:02X})',xored,80)
                            current=xored; seen.add(current); continue
                    except: pass

            # ── 15. Unknown — show analysis summary ───────────────
            print(f"\n{div}")
            if step == 0:
                print(f"  {Y}[?] Could not automatically identify encoding.")
                print(f"  {Y}    Entropy  : {-sum((v/len(current))*math.log2(v/len(current)) for v in Counter(current).values()):.2f} bits/char")
                print(f"  {Y}    Length   : {len(current)}")
                print(f"  {Y}    Charset  : {'alpha+digits' if current.isalnum() else 'mixed'}")
                print(f"  {Y}    Possible : Vigenere / custom substitution / unknown key cipher")
                print(f"\n  {LG}[RAW INPUT — no decoding applied]")
            else:
                print(f"  {LG}[FINAL DECODED OUTPUT]")
            print(f"  {BRIGHT}{current}{RESET}")
            print(div)
            break

# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    print(BANNER)
    engine = Hashnamer()
    print(f"  {C}[*] Wordlists : {engine.wl.summary()}")
    print(f"  {C}[*] Built-in  : {len(BUILTIN_WORDLIST)} passwords loaded")
    print(f"  {C}[*] Methods   : 46 detection/decode methods active")
    print(f"  {C}[*] HIBP API  : k-anonymity mode (privacy-safe){RESET}")
    print(f"\n  {Y}Paste any encoded/hashed/encrypted data and press Enter.")
    print(f"  {Y}Type 'exit' or Ctrl+C to quit.{RESET}\n")
    try:
        while True:
            first = input(f"{M}INPUT{RESET} > ").strip()
            if not first: continue
            if first.lower() == 'exit': break
            lines = [first]
            if len(first) >= 60:
                print(f"  {C}(Multi-line mode — type END to finish){RESET}")
                while True:
                    l = input('        ').strip()
                    if l.upper() == 'END': break
                    lines.append(l)
            engine.process('\n'.join(lines))
    except (EOFError, KeyboardInterrupt):
        print(f"\n\n  {R}[!] Exiting HASHNAMER v4. Stay sharp.{RESET}\n")

if __name__ == '__main__':
    main()
