"""
milenage_aka.py

Wraps the milenage f1-5 functions into an interface for DEMO-AKA

compute() and compute_w_masked_sqn() handles the asymmetry between HOME and USIM.
compute() HOME side, SQN is known
compute_w_masked_sqn() USIM side, SQN is masked
"""

from helpers import encrypt, xor,hex_to_byte, r1, r2, r3, r4, c1, c2, c3, c4
from milenage import f1 as _f1, f2 as _f2, f3 as _f3, f4 as _f4, f5 as _f5

class Milenage:
    # Milenage authentication and key derivation.
    # Initialise with K and OPc, call compute() or compute_w_masked_sqn(),
    # then get results via f1()-f5().
    def __init__(self, K: bytes, OPc: bytes):
        assert len(K) == 16, "K must be 16 bytes"
        assert len(OPc) == 16, "OPc must be 16 bytes"
        self.K = K
        self.OPc = OPc
        self._temp = None
        self._MACA = None
        self._RES = None
        self._CK = None
        self._IK = None
        self._AK = None

    def _compute_temp(self, RAND: bytes):
        assert len(RAND) == 16, "RAND must be 16 bytes"
        self._temp = encrypt(self.K, xor(RAND, self.OPc))

    def compute(self, RAND: bytes, SQN: bytes, AMF: bytes):
        # HOME side: computes milenage outputs when SQN is known.
        assert len(SQN) == 6, "SQN must be 6 bytes"
        assert len(AMF) == 2, "AMF must be 2 bytes"
        self._compute_temp(RAND)
        in1 = SQN + AMF + SQN + AMF
        self._MACA = hex_to_byte(_f1(self.K, self._temp, in1, self.OPc, r1, c1))
        self._RES = hex_to_byte(_f2(self.K, self._temp, self.OPc, r2, c2))
        self._CK = hex_to_byte(_f3(self.K, self._temp, self.OPc, r3, c3))
        self._IK = hex_to_byte(_f4(self.K, self._temp, self.OPc, r4, c4))
        self._AK = hex_to_byte(_f5(self.K, self._temp, self.OPc, r2, c2))

    def compute_w_masked_sqn(self, RAND: bytes, MSQN: bytes, AMF: bytes):
        # USIM side: computes milenage outputs when SQN is masked.
        assert len(MSQN) == 6, "MSQN must be 6 bytes"
        assert len(AMF) == 2, "AMF must be 2 bytes"
        self._compute_temp(RAND)
        self._AK = hex_to_byte(_f5(self.K, self._temp, self.OPc, r2, c2))
        SQN = xor(MSQN, self._AK)
        in1 = SQN + AMF + SQN + AMF
        self._MACA = hex_to_byte(_f1(self.K, self._temp, in1, self.OPc, r1, c1))
        self._RES = hex_to_byte(_f2(self.K, self._temp, self.OPc, r2, c2))
        self._CK = hex_to_byte(_f3(self.K, self._temp, self.OPc, r3, c3))
        self._IK = hex_to_byte(_f4(self.K, self._temp, self.OPc, r4, c4))

    def f1(self) -> bytes:
        if self._MACA is None: raise RuntimeError("Call compute() first")
        return self._MACA

    def f2(self) -> bytes:
        if self._RES is None: raise RuntimeError("Call compute() first")
        return self._RES

    def f3(self) -> bytes:
        if self._CK is None: raise RuntimeError("Call compute() first")
        return self._CK

    def f4(self) -> bytes:
        if self._IK is None: raise RuntimeError("Call compute() first")
        return self._IK

    def f5(self) -> bytes:
        if self._AK is None: raise RuntimeError("Call compute() first")
        return self._AK