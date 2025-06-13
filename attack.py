from padding_oracle import PaddingOracle, BLOCK_SIZE

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR entre dos secuencias de bytes del mismo tamaño"""
    return bytes([x ^ y for x, y in zip(a, b)])

def create_padding_block(pad_value: int, known_intermediate: bytearray, block_size: int) -> bytearray:
    """Crea una máscara de padding para los bytes ya descubiertos"""
    mask = bytearray(block_size)
    for j in range(1, pad_value):
        mask[-j] = known_intermediate[-j] ^ pad_value
    return mask

def find_valid_guess(x1: bytearray, x2: bytes, oracle: PaddingOracle, position: int, intermediate: bytearray) -> int:
    """Prueba valores posibles en la posición indicada hasta encontrar uno que dé padding válido"""
    for guess in range(256):
        x1_guess = x1[:]
        x1_guess[-position] ^= guess

        # Aplicar la máscara de padding a los bytes descubiertos
        mask = create_padding_block(position, intermediate, BLOCK_SIZE)
        for j in range(1, position):
            x1_guess[-j] ^= mask[-j]

        if oracle.is_valid_padding(bytes(x1_guess), x2):
            return guess
    raise ValueError("No se encontró un padding válido")  # debería ser imposible

def padding_oracle_attack(x1: bytes, x2: bytes, oracle: PaddingOracle) -> bytes:
    """Recupera el mensaje plano m2 usando solo el oracle y los bloques cifrados x1, x2"""
    recovered = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    x1 = bytearray(x1)

    for i in range(1, BLOCK_SIZE + 1):
        guess = find_valid_guess(x1, x2, oracle, i, intermediate)
        intermediate[-i] = guess ^ i
        recovered[-i] = intermediate[-i] ^ x1[-i]

    return bytes(recovered)