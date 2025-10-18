import string

ALPH = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
ALPH_Upper = ALPH.upper()
ALPHABET = ALPH + ALPH_Upper
print(ALPHABET)
def decrypt_text(text, key):
    decrypted_text = ""
    for i in range(len(text)):
        key_index = i % len(key)
        key_char = key[key_index]
        text_char = text[i]
        decrypted_letter_index = (ALPHABET.index(text_char) - ALPHABET.index(key_char)) % len(ALPHABET)
        decrypted_text += ALPHABET[decrypted_letter_index]
    return decrypted_text

def encrypt_text(text, key):
    encrypted_text = ""
    for i in range(len(text)):
        key_index = i % len(key)
        key_char = key[key_index]
        text_char = text[i]
        encrypted_letter_index = (ALPHABET.index(text_char) + ALPHABET.index(key_char)) % len(ALPHABET)
        encrypted_text += ALPHABET[encrypted_letter_index]
    return encrypted_text


some_text = 'криптографічніметодизахистуінформації'
key = "Федірко"


protected_text = encrypt_text(some_text, key)
print(protected_text)

decrypted_text = decrypt_text(protected_text, key)
print(f"Decrypted Text: {decrypted_text}")
