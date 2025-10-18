import secrets, math, base64

# --- number theory helpers ---
def _egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def _modinv(a, m):
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def _is_probable_prime(n, k=16):
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53]
    for p in small:
        if n == p: return True
        if n % p == 0: return False
    # n-1 = d*2^r
    d = n - 1; r = 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits=512):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # найстарший біт + непарне
        if _is_probable_prime(cand):
            return cand

class RSAEdu:
    def __init__(self, n:int, e:int, d:int):
        self.n, self.e, self.d = n, e, d
        self.modlen = (n.bit_length() + 7) // 8              # довжина шифроблоку у байтах
        self.plain_block = (n.bit_length() - 1) // 8         # макс. довжина відкритоблоку (гарантує int<mод)

    @classmethod
    def generate(cls, bits=1024, e=65537):
        half = bits // 2
        while True:
            p = _gen_prime(half)
            q = _gen_prime(half)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) == 1:
                d = _modinv(e, phi)
                return cls(n, e, d)

    # --- core ---
    def encrypt_bytes(self, data: bytes) -> bytes:
        out = bytearray()
        k = self.plain_block
        for i in range(0, len(data), k):
            chunk = data[i:i+k]
            m = int.from_bytes(chunk, 'big')
            if m >= self.n:
                raise ValueError("Plain block >= n; increase modulus size")
            c = pow(m, self.e, self.n)
            out.extend(c.to_bytes(self.modlen, 'big'))  # фіксована довжина
        return bytes(out)

    def decrypt_bytes(self, ct: bytes) -> bytes:
        if len(ct) % self.modlen != 0:
            raise ValueError("Ciphertext length not multiple of block size")
        out = bytearray()
        for i in range(0, len(ct), self.modlen):
            block = ct[i:i+self.modlen]
            c = int.from_bytes(block, 'big')
            m = pow(c, self.d, self.n)
            mb = m.to_bytes((m.bit_length() + 7) // 8, 'big')  # зняти провідні нулі блоку
            out.extend(mb)
        return bytes(out)

    # --- text helpers ---
    def encrypt_text_to_b64(self, text: str) -> str:
        pt = text.encode('utf-8')
        ct = self.encrypt_bytes(pt)
        return base64.b64encode(ct).decode('ascii')

    def decrypt_b64_to_text(self, b64: str) -> str:
        ct = base64.b64decode(b64.encode('ascii'))
        pt = self.decrypt_bytes(ct)
        return pt.decode('utf-8')

if __name__ == "__main__":
    msg = ("Cryptography is fun and educational! Learning RSA encryption and decryption "
           "with Python helps understand public key cryptosystems.")
    rsa = RSAEdu.generate(bits=1024, e=65537)
    b64 = rsa.encrypt_text_to_b64(msg)
    back = rsa.decrypt_b64_to_text(b64)
    print("n bits:", rsa.n.bit_length())
    print("ok:", back == msg)
    print("cipher (b64, first 120):", b64[:120] + ("..." if len(b64) > 120 else ""))
    print(f"decrypted:, {back} ")
