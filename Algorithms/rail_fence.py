def rail_fence_encrypt(plaintext: str, rails: int) -> str:
    if rails <= 1 or rails >= len(plaintext):
        return plaintext

    # Use list of strings (Unicode safe)
    fence = [""] * rails

    row = 0
    direction = 1

    for char in plaintext:
        fence[row] += char

        # Switch direction
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1

        row += direction

    return "".join(fence)


def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    if rails <= 1 or rails >= len(ciphertext):
        return ciphertext

    n = len(ciphertext)

    # Step 1: Build zigzag pattern (store row index only)
    pattern = []
    row = 0
    direction = 1

    for _ in range(n):
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction

    # Step 2: Count characters expected in each row
    row_counts = [pattern.count(r) for r in range(rails)]

    # Step 3: Split ciphertext into rails
    rails_list = []
    index = 0
    for count in row_counts:
        rails_list.append(list(ciphertext[index : index + count]))
        index += count

    # Step 4: Rebuild plaintext following zigzag pattern
    result = []
    rail_positions = [0] * rails

    for r in pattern:
        result.append(rails_list[r][rail_positions[r]])
        rail_positions[r] += 1

    return "".join(result)