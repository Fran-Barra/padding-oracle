from typing import List

BLOCK_SIZE = 8

class PaddingOracle:
    def __init__(self, key: bytes):
        self.key = key

    def decrypt_block(self, block: bytes) -> bytes:
        return bytes([b ^ k for b, k in zip(block, self.key)])

    def is_valid_padding(self, x1: bytes, x2: bytes) -> bool:
        decrypted = self.decrypt_block(x2)
        m2 = bytes([a ^ b for a, b in zip(x1, decrypted)])
        padding = m2[-1]
        if padding < 1 or padding > BLOCK_SIZE:
            return False
        return m2.endswith(bytes([padding] * padding))