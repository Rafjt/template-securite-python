import hashlib

from src.tp3.utils.captcha  import Captcha
import requests
import re


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""

        if "captcha1" in url:
            self.challenge = 1
        elif "captcha2" in url:
            self.challenge = 2
        elif "captcha3" in url:
            self.challenge = 3
        elif "captcha4" in url:
            self.challenge = 4

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.value
        self.captcha_value = captcha.get_value()
        self.current_session = captcha.session
        if self.challenge == 1:
            # Dans le test initiale on avait self.current = 1000 mais pour aller plus vite on le commente une fois trouvé
            self.current = 1578
        elif self.challenge == 2:
            if not hasattr(self, "current"):
                # Dans le test initiale on avait self.current = 2000 mais pour aller plus vite on le commente une fois trouvé
                self.current = 2756
        elif self.challenge == 3:
            if not hasattr(self, "current"):
                # Dans le test initiale on avait self.current = 3000 mais pour aller plus vite on le commente une fois trouvé
                self.current = 3889
        elif self.challenge == 4:
            if not hasattr(self, "current"):
                # Dans le test initiale on avait self.current = 7000 mais pour aller plus vite on le commente une fois trouvé
                self.current = 7629
            else:
                self.current += 1

        self.flag_value = self.current
        self.payload = {'flag': self.flag_value, 'captcha': self.captcha_value, 'submit': 'envoyer'}
        insert = str(self.flag_value) + str(self.captcha_value)
        self.hashed_payload = hashlib.md5(insert.encode()).hexdigest()
        #print(self.hashed_payload)
        print(self.payload)

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        headers = {
            "Magic-Word": "please"
        }
        if self.challenge == 4:
            self.response = self.current_session.post(
                self.url,
                headers=headers,
                data=self.payload
            )
            print(len(self.response.text))
        else:
            self.response = self.current_session.post(self.url,data=self.payload,)
            print(len(self.response.text))


    def process_response(self):
        """
        Processes the response.
        en gros regarder si la réponse c'est une 200 et en extraire le flag IMO
        """
        if self.challenge == 1:
            text = self.response.text.lower()

            if "incorrect flag" in text:
                return False

            if "incorrect captcha" in text:
                return False

            if "correct" in text:
                self.valid_flag = self.flag_value
                print(self.response.text)
                print("FLAG TROUVEE :", self.valid_flag)
                return True

        elif self.challenge == 2:
            if len(self.response.text) == 1246 or len(self.response.text) == 1017:
                return False
            self.valid_flag = self.flag_value
            print(self.response.text)
            print("FLAG TROUVEE :", self.valid_flag)
            return True

        elif self.challenge == 3:
            if len(self.response.text) == 1251 or len(self.response.text) == 1240:
                return False
            self.valid_flag = self.flag_value
            print(self.response.text)
            print("FLAG TROUVEE :", self.valid_flag)
            return True

        if self.challenge == 4:

            text = self.response.text.lower()

            if "incorrect flag" in text:
                return False

            if "incorrect captcha" in text:
                return False

            if "correct" in text:
                self.valid_flag = self.flag_value

                print(self.response.text)

                print("FLAG TROUVEE :", self.valid_flag)

                return True

    def get_flag(self):
        """
        Returns the valid flag.
        juste un geter
        Returns:
            str: The valid flag.
        """
        return self.valid_flag
