from padding_oracle import PaddingOracle, BLOCK_SIZE

def padding_oracle_attack(x1: bytes, x2: bytes, oracle: PaddingOracle) -> bytes:
    recovered = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    x1 = bytearray(x1)

    for i in range(1, BLOCK_SIZE + 1):
        pad = i
        for b in range(256):
            x1_guess = x1[:]
            x1_guess[-i] ^= b

            for j in range(1, i):
                x1_guess[-j] ^= intermediate[-j] ^ pad

            if oracle.is_valid_padding(bytes(x1_guess), x2):
                intermediate[-i] = b ^ pad
                recovered[-i] = intermediate[-i] ^ x1[-i]
                break

    return bytes(recovered)
