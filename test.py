import unittest
from padding_oracle import PaddingOracle, BLOCK_SIZE
from attack import padding_oracle_attack

class TestPaddingOracleAttack(unittest.TestCase):
    def test_attack_recovers_original_message(self):
        key = b'\x10\x20\x30\x40\x50\x60\x70\x80'
        original_message = b'HOLAMUND'
        oracle = PaddingOracle(key)

       
        x2 = bytes([a ^ b for a, b in zip(original_message, key)])
        x1 = bytes([0x00] * BLOCK_SIZE) 

        recovered_message = padding_oracle_attack(x1, x2, oracle)

        self.assertEqual(recovered_message, original_message)

if __name__ == '__main__':
    unittest.main()
