# channel/ddh_ot.py
from src.common.crypto.ddh_group import DDHGroup
from src.common.crypto.prf import prf_labeled

class DDHOTSender:
    def __init__(self, group: DDHGroup):
        self.group = group
        self.a = self.group.get_random_exponent()  # Sender's secret exponent
        self.A = self.group.power(self.group.g, self.a)  # Sender's public key A

    def respond(self, B: int, m0: bytes, m1: bytes) -> tuple[bytes, bytes]:
        # Validate public key B
        if not (1 < B < self.group.p):
            raise ValueError("Invalid public key B")

        # Validate that B is in the prime-order subgroup
        if pow(B, self.group.q, self.group.p) != 1:
            raise ValueError("B not in prime-order subgroup")

        # Validate message lengths
        if len(m0) != len(m1):
            raise ValueError("Messages must be of the same length")
        
        # Compute shared secrets
        K0 = self.group.power(B, self.a)  # K0 = B^a
        A_inv = self.group.inverse(self.A)
        K1 = self.group.power((B * A_inv) % self.group.p, self.a)

        # Derive pads via PRF
        # The key should be a consistent byte length
        key_byte_len = (self.group.q.bit_length() + 7) // 8
        K0b = K0.to_bytes(key_byte_len, 'big')
        K1b = K1.to_bytes(key_byte_len, 'big')
        pad0 = prf_labeled(K0b, b"OT2|m0", len(m0))
        pad1 = prf_labeled(K1b, b"OT2|m1", len(m1))

        # Mask messages
        c0 = bytes(x ^ y for x, y in zip(m0, pad0))
        c1 = bytes(x ^ y for x, y in zip(m1, pad1))

        return c0, c1

class DDHOTReceiver:
    def __init__(self, group: DDHGroup, choice_bit: int):
        if choice_bit not in (0, 1):
            raise ValueError("choice_bit must be 0 or 1")
        self.group = group
        self.choice_bit = choice_bit
        
        # Generate the receiver's secret exponent 'b' during initialization
        self.b = self.group.get_random_exponent()
        self.A = None # To be received from sender

    def generate_B(self, A: int) -> int:
        self.A = A 
        if self.choice_bit == 0:
            # If choice is 0, B = g^b
            return self.group.power(self.group.g, self.b)
        else: # choice_bit == 1
            # If choice is 1, B = A * g^b
            g_pow_b = self.group.power(self.group.g, self.b)
            return (A * g_pow_b) % self.group.p

    def recover(self, c_tuple: tuple[bytes, bytes]) -> bytes:
        if self.A is None:
            raise RuntimeError("A not set on receiver")
        # Receiver always computes the key K as A^b
        K = self.group.power(self.A, self.b) # g^{ab}
        
        # Choose the correct ciphertext
        chosen_ciphertext = c_tuple[self.choice_bit]

        # Derive the pad using the computed key K
        key_byte_len = (self.group.q.bit_length() + 7) // 8
        Kb = K.to_bytes(key_byte_len, 'big')

        if self.choice_bit == 0:
            label = b"OT2|m0"
        else:
            label = b"OT2|m1"
            
        pad = prf_labeled(Kb, label, len(chosen_ciphertext))
        
        # Unmask the message
        return bytes(x ^ y for x, y in zip(chosen_ciphertext, pad))