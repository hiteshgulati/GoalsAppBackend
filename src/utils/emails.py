import requests

class Msg91Mailer:

    def __init__(self, authkey: str, domain: str, from_email: str):
        self.authkey = authkey
        self.domain = domain
        self.from_email = from_email
        self.url = "https://control.msg91.com/api/v5/email/send"

    def send_email_using_template(self, to_email: str, to_name: str, template_id: str, variables: dict):
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authkey": self.authkey
        }

        payload = {
            "recipients": [
                {
                    "to": [
                        {
                            "email": to_email,
                            "name": to_name
                        }
                    ],
                    "variables": variables
                }
            ],
            "from": {
                "email": self.from_email
            },
            "domain": self.domain,
            "template_id": template_id
        }

        response = requests.post(self.url, json=payload, headers=headers)
        print(response.text)
