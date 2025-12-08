# -------------------- DES Key Generation --------------------

# Permutation Choice 1 (PC-1)
PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

# Permutation Choice 2 (PC-2)
PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

# Left Shifts Table
SHIFT_TABLE = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# -------------------- Utility Functions --------------------

def hex_to_bin(hex_key):
    """Convert 16-character hex to 64-bit binary string"""
    return bin(int(hex_key, 16))[2:].zfill(64)

def permute(bits, table):
    """Permute bits according to table"""
    return ''.join(bits[i-1] for i in table)

def left_shift(bits, n):
    """Left shift a bit string by n positions"""
    return bits[n:] + bits[:n]

# -------------------- Key Validation --------------------

def validate_des_key(input_key):
    """
    Validate user input:
    - Hexadecimal: 16 hex characters
    - Binary: 64 bits
    Returns 'hex', 'bin', or None if invalid
    """
    input_key = input_key.strip()

    if len(input_key) == 16:
        try:
            int(input_key, 16)
            return 'hex'
        except ValueError:
            return None
    elif len(input_key) == 64:
        if all(c in '01' for c in input_key):
            return 'bin'
        else:
            return None
    else:
        return None

# -------------------- DES Round Key Generation --------------------

def des_key_generation(key_input):
    """
    Generate 16 DES round keys from user input (Hex or Binary)
    Returns list of 16 round keys as 48-bit binary strings
    Raises ValueError for invalid input
    """
    key_type = validate_des_key(key_input)
    if key_type is None:
        raise ValueError("Invalid key! Must be 16-hex digits or 64-bit binary.")

    # Convert to 64-bit binary if input is hex
    if key_type == 'hex':
        key64 = hex_to_bin(key_input)
    else:
        key64 = key_input

    # Apply PC-1 to get 56-bit key
    key56 = permute(key64, PC1)
    C = key56[:28]
    D = key56[28:]

    round_keys = []
    for i in range(16):
        # Left shift according to SHIFT_TABLE
        C = left_shift(C, SHIFT_TABLE[i])
        D = left_shift(D, SHIFT_TABLE[i])
        CD = C + D

        # Apply PC-2 to get 48-bit round key
        Ki = permute(CD, PC2)
        round_keys.append(Ki)

    return round_keys
