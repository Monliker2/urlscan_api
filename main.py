import requests
import json
import time
import sys
from dotenv import load_dotenv
from os import getenv

load_dotenv()
API =  getenv('API')

def main(url):
    headers = {'API-Key':f'{API}','Content-Type':'application/json'}
    data = {"url": f"{url}", "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    uuid = response.json()['uuid']

    response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/',headers=headers, data=json.dumps(data))
    while response.status_code == 404:
        time.sleep(2)
        response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/', headers=headers, data=json.dumps(data))
    print(response.json()["verdicts"]["overall"]["malicious"])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Использование: python script.py https://example.com/page")
        sys.exit(1)
    main(sys.argv[1])