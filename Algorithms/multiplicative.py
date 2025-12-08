# multiplicative.py
# Simple Multiplicative Cipher mod 26
# E(x) = (a * x) mod 26
# D(x) = (a_inv * x) mod 26

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
MOD = 26


# --------- Helper Functions ---------
def egcd(a, b):
    """Extended Euclidean Algorithm. Returns gcd(a,b) and coefficients."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a, m=26):
    """Returns modular inverse of a mod m, or raises ValueError."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"Key '{a}' is invalid (gcd({a}, 26) ≠ 1), no inverse exists.")
    return x % m


def validate_key(a):
    """Ensures key is valid for multiplicative cipher."""
    if not isinstance(a, int):
        raise ValueError("Key must be an integer.")
    if a <= 0 or a >= 26:
        raise ValueError("Key must be between 1 and 25.")
    g, _, _ = egcd(a, 26)
    if g != 1:
        raise ValueError(f"Key '{a}' is not coprime with 26 (invalid key).")


# --------- Encryption ---------
def encrypt(plaintext, a):
    """Encrypts using multiplicative cipher."""
    validate_key(a)
    result = ""

    for ch in plaintext:
        if ch.isalpha():
            is_upper = ch.isupper()
            idx = ALPHABET.index(ch.lower())
            new_idx = (a * idx) % MOD
            new_ch = ALPHABET[new_idx]
            result += new_ch.upper() if is_upper else new_ch
        else:
            result += ch  # Keep spaces, symbols, numbers

    return result


# --------- Decryption ---------
def decrypt(ciphertext, a):
    """Decrypts using multiplicative cipher."""
    validate_key(a)
    a_inv = mod_inverse(a)

    result = ""

    for ch in ciphertext:
        if ch.isalpha():
            is_upper = ch.isupper()
            idx = ALPHABET.index(ch.lower())
            new_idx = (a_inv * idx) % MOD
            new_ch = ALPHABET[new_idx]
            result += new_ch.upper() if is_upper else new_ch
        else:
            result += ch

    return result


# Optional test when running the file alone
if __name__ == "__main__":
    msg = "Hello World"
    key = 5
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print("Plain:", msg)
    print("Encrypted:", enc)
    print("Decrypted:", dec)
