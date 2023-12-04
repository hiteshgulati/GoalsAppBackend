import requests

def is_isd_code_approved(approved_isd_codes: str, request_isd_code: str) -> bool:
    isd_code_list: list[str] = approved_isd_codes.split(",")
    if request_isd_code in isd_code_list:
        return True
    else:
        return False

class Msg91SMSClient:

    def __init__(self, authkey: str):
        self.authkey = authkey
        self.url = "https://control.msg91.com/api/v5/flow/"

    def send_otp_sms(self, mobile_number: str, otp: str, dur_mins_str: str)->str:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authkey": self.authkey
        }

        payload = {
            "template_id": "65695e68d6fc0542555e9012",
            "short_url": "0",
            "recipients": [
                {
                    "mobiles": mobile_number,
                    "otp": otp,
                    "dur": dur_mins_str
                }
            ]
        }
        # print(f"URL: {self.url}")
        # print(f"Headers: {headers}")
        # print(f"Payload: {payload}")
        response = requests.post(self.url, json=payload, headers=headers)
        return response.text
