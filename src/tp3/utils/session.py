from src.tp3.utils.captcha import Captcha
import random

s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0"})

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

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()
        ran = random.randrange(1000, 2000, 1)
        print(ran)
        self.captcha_value = captcha.value
        self.captcha_value = captcha.get_value()
        self.flag_value = ran
        self.payload = {'flag': ran, 'captcha': self.captcha_value}

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        self.response = requests.post(self.url, data=self.payload)
        print(self.response.status_code)

    def process_response(self):
        """
        Processes the response.
        en gros regarder si la réponse c'est une 200 et en extraire le flag IMO
        """

    def get_flag(self):
        """
        Returns the valid flag.
        juste un geter
        Returns:
            str: The valid flag.
        """
        return self.valid_flag
