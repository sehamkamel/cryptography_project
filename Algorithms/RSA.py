# ---------------- RSA logic (paper-style letters, correct decryption) ----------------
import math

# ---------------- Prime helpers ----------------
def is_prime(n):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r = int(math.isqrt(n))
    for i in range(3, r + 1, 2):
        if n % i == 0: return False
    return True

def next_prime(x):
    while not is_prime(x):
        x += 1
    return x

# ---------------- Extended Euclidean ----------------
def egcd(a, b):
    if a == 0: return b,0,1
    g,x1,y1=egcd(b%a,a)
    return g, y1-(b//a)*x1, x1

def modinv(a,m):
    g,x,_=egcd(a,m)
    if g!=1: raise ValueError("Inverse does not exist")
    return x%m

# ---------------- Generate RSA Keys ----------------
def generate_keys(p,q):
    if not is_prime(p): p = next_prime(p)
    if not is_prime(q): q = next_prime(q)
    if p==q: q = next_prime(q+1)
    n = p*q
    phi=(p-1)*(q-1)
    for e_try in [3,5,17,257,65537]:
        if math.gcd(e_try,phi)==1:
            e=e_try
            break
    d=modinv(e,phi)
    return (e,n),(d,n)

# ---------------- Letter Conversion ----------------
def char_to_num(ch):
    ch = ch.upper()
    if 'A' <= ch <= 'Z':
        return ord(ch) - ord('A')
    else:
        return None  # keep non-letter chars

def num_to_char(num):
    return chr(num + ord('A'))

# ---------------- Encrypt ----------------
def rsa_encrypt(message, public_key):
    e,n = public_key
    encrypted = ""
    for ch in message:
        num = char_to_num(ch)
        if num is None:
            encrypted += ch  # keep non-letters
        else:
            # compute m^e mod n
            c = pow(num, e, n)
            # wrap around only for display as letter
            encrypted += num_to_char(c % 26)
    return encrypted

# ---------------- Decrypt ----------------
def rsa_decrypt(cipher, private_key):
    d,n = private_key
    decrypted = ""
    for ch in cipher:
        num = char_to_num(ch)
        if num is None:
            decrypted += ch
        else:
            m = pow(num, d, n)
            decrypted += num_to_char(m % 26)  # wrap around for letter display
    return decrypted
