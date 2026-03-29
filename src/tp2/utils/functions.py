import pylibemu

class Functions:
    def __init__(self):
        self.shellcode = ""
        self.value = ""

    def get_shellcode_strings(self):
        return self.shellcode

    def  get_pylibemu_analysis(self):
        return True

    def get_capstone_analysis(self):
        return True

    def get_llm_analysis(self):
        return True