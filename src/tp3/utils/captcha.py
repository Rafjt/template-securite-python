from PIL import Image
import pytesseract
import requests
import re


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        img = Image.open(self.image)

        text = pytesseract.image_to_string(img, config='--psm 7 digits')

        text = re.sub(r"\D", "", text)

        self.value = text

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        if not hasattr(self, "session"):
            self.session = requests.Session()
        self.session.get(self.url)

        img_url = self.url + "../captcha.php"

        r = self.session.get(img_url)

        with open("captcha.png", "wb") as f:
            f.write(r.content)

        self.image = "captcha.png"

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
