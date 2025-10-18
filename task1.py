import string

ALPH = string.ascii_lowercase

def caesar_shift(text, shift):
    new_text = ""
    for i in text:
        if i in ALPH:
            decrypted_letter = (ALPH.index(i) + shift) % 26
            new_text += ALPH[decrypted_letter]
    return new_text


encrypted_text = 'vppanlwxlyopyncjae'

for k in range(0, len(ALPH)):
    decrypted_text = caesar_shift(encrypted_text, k)
    print(f"Text: {decrypted_text} key: {k}")
