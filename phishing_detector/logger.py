import time

class Logger:
    @staticmethod
    def info(msg):
        print(f"[INFO] {msg}")

    @staticmethod
    def ml(msg):
        print(f"[ML] {msg}")

    @staticmethod
    def security(msg):
        print(f"[SECURITY] {msg}")

    @staticmethod
    def crypto_trad(msg):
        print(f"[CRYPTO-TRAD] {msg}")

    @staticmethod
    def crypto_modern(msg):
        print(f"[CRYPTO-MODERN] {msg}")

    @staticmethod
    def warning(msg):
        print(f"[WARNING] {msg}")

    @staticmethod
    def error(msg):
        print(f"[ERROR] {msg}")
