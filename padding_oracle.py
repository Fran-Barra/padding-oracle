from typing import List

BLOCK_SIZE = 8

class PaddingOracle:
    def __init__(self, key: bytes):
        self.key = key

    def decrypt_block(self, block: bytes) -> bytes:
        """Simula un descifrado simple con XOR clave."""
        return bytes([b ^ k for b, k in zip(block, self.key)])

    def get_plaintext_block(self, x1: bytes, x2: bytes) -> bytes:
        """Realiza el paso CBC: DK(x2) ⊕ x1 = m2"""
        decrypted = self.decrypt_block(x2)
        return bytes([a ^ b for a, b in zip(x1, decrypted)])

    def extract_padding_value(self, block: bytes) -> int:
        """Devuelve el valor del padding (último byte del bloque)"""
        return block[-1]

    def has_valid_padding(self, block: bytes) -> bool:
        """Verifica si el bloque termina en un padding PKCS#7 válido"""
        padding = self.extract_padding_value(block)
        if padding < 1 or padding > BLOCK_SIZE:
            return False
        return block.endswith(bytes([padding] * padding))

    def is_valid_padding(self, x1: bytes, x2: bytes) -> bool:
        """Interfaz principal del oráculo: ¿el padding es válido?"""
        m2 = self.get_plaintext_block(x1, x2)
        return self.has_valid_padding(m2)