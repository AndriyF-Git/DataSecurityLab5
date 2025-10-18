import secrets, math

# --- number theory helpers ---
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def is_probable_prime(n, k=16):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small_primes:
        if n == p: return True
        if n % p == 0: return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits=256):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1  # top bit + odd
        if is_probable_prime(cand):
            return cand

def generate_rsa_keypair(bits=512, e=65537):
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (p, q, n, phi, e, d)

def rsa_encrypt(M, e, n):
    if not (0 <= M < n):
        raise ValueError("Message out of range")
    return pow(M, e, n)

def rsa_decrypt(C, d, n):
    return pow(C, d, n)

# === demo ===
p, q, n, phi, e, d = generate_rsa_keypair(bits=512, e=65537)
M = 100
C = rsa_encrypt(M, e, n)
M_back = rsa_decrypt(C, d, n)

print("n bits =", n.bit_length())
print("n =", n)
print("p =", p)
print("q =", q)
print("e =", e)
print("d bits =", d.bit_length())
print("M =", M)
print("C =", C)
print("M' =", M_back)
