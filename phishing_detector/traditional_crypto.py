from .logger import Logger

def caesar_encrypt(text, shift=3):
    """
    Encrypts a plaintext string using the Caesar Cipher.
    """
    Logger.crypto_trad("Encrypting logs using Caesar Cipher...")
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            encrypted_text += chr((ord(char) - start + shift) % 26 + start)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift=3):
    """
    Decrypts a Caesar Cipher encrypted string.
    """
    return caesar_encrypt(text, -shift)

def save_encrypted_log(crypto_result, filepath="logs.txt"):
    """
    Saves the Caesar encrypted log payload to a file.
    """
    with open(filepath, 'a', encoding="utf-8") as f:
        f.write(crypto_result + "\n" + "-"*40 + "\n")
