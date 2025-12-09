def onetimepad_encrypt(message: str, key: str) -> str:

    extended_key = (key * ((len(message) // len(key)) + 1))[: len(message)]
    return "".join(str(int(m) ^ int(k)) for m, k in zip(message, extended_key))


def onetimepad_decrypt(ciphertext: str, key: str) -> str:

    extended_key = (key * ((len(ciphertext) // len(key)) + 1))[: len(ciphertext)]
    return "".join(str(int(c) ^ int(k)) for c, k in zip(ciphertext, extended_key))