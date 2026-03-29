from pwn import *
import binascii
import base64
import re


class Utils:
    MORSE_MAP = {
        '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e', '..-.': 'f', '--.': 'g',
        '....': 'h', '..': 'i', '.---': 'j', '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n',
        '---': 'o', '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't', '..-': 'u',
        '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y', '--..': 'z',
        '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'
    }

    @staticmethod
    def solve():
        dist = remote('31.220.95.27', 13337)

        try:
            while True:
                dist.recvuntil(b'A d\xc3\xa9coder: ')
                challenge = dist.recvline().decode().strip()
                decod = ""
                if '.' in challenge or '-' in challenge:
                    decod = "".join([Utils.MORSE_MAP.get(c, '') for c in challenge.split(' ')])
                elif re.fullmatch(r'[0-9a-fA-F]+', challenge):
                    decod = binascii.unhexlify(challenge).decode()
                else:
                    decod = base64.b64decode(challenge).decode()
                dist.sendline(decod.encode())

        except EOFError:
            print(dist.recvall().decode())
        except Exceptdistn as e:
            print(f"erreur: {e}")
            dist.interactive()


if __name__ == "__main__":
    Utils.solve()