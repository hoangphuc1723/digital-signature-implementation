import random
from sympy import isprime

# Function to check if a number is prime
def is_prime(n):
    return isprime(n)

# Function to generate a prime number of specified length


def generate_prime(length):
    while True:
        prime_candidate = random.randint(2**(length-1), 2**length - 1)
        if is_prime(prime_candidate):
            return prime_candidate

# Function to calculate the greatest common divisor (GCD) of two numbers


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to find the modular inverse of a number


def mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1,
            u2 - q * v2,
            u3 - q * v3,
            v1,
            v2,
            v3,
        )
    return u1 % m

# Function to generate RSA keys


def generate_rsa_keys(key_length):
    # Generate two distinct prime numbers
    p = generate_prime(key_length // 2)
    q = generate_prime(key_length // 2)

    # Compute modulus
    modulus = p * q

    # Compute Euler's totient function
    phi = (p - 1) * (q - 1)

    # Choose encryption exponent e (usually a small prime number)
    e = 65537

    # Compute decryption exponent d
    d = mod_inverse(e, phi)

    return (e, modulus), (d, modulus)

# Function to encrypt a message using RSA


def encrypt(message, public_key):
    e, modulus = public_key
    encrypted = [pow(ord(c), e, modulus) for c in message]
    return encrypted

# Function to decrypt a message using RSA


def decrypt(ciphertext, private_key):
    d, modulus = private_key
    decrypted = [chr(pow(c, d, modulus)) for c in ciphertext]
    return ''.join(decrypted)


# Example usage
message = "HELLO"

# Generate RSA keys with a key length of 512 bits
public_key, private_key = generate_rsa_keys(512)

# Encrypt the message using the public key
encrypted_message = encrypt(message, public_key)

# Decrypt the ciphertext using the private key
decrypted_message = decrypt(encrypted_message, private_key)

print("Original Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)
