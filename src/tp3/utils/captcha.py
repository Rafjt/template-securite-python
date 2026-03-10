from PIL import Image
import pytesseract
import requests

class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = "FIXME"

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        # choper la session
        if not hasattr(self, "session"):
            self.session = requests.Session()

            # ouvrir la page captcha
        r = self.session.get(self.url)

        # récupérer l'image captcha

        img_url = self.url + "../captcha.php"
        img = requests.get(img_url)

        with open("captcha.php", "wb") as f:
            f.write(img.content)

        self.image = "captcha.png"

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
