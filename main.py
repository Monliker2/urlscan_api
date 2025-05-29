import requests
import json
import time
import sys
from dotenv import load_dotenv
from os import getenv
import logging
import logging.handlers


# Настройка логгера
logger = logging.getLogger('urlscan_logger')
logger.setLevel(logging.INFO)

# Отправка в syslog
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)


load_dotenv()
API =  getenv('API')

def main(url):
    headers = {'API-Key': f'{API}', 'Content-Type': 'application/json'}
    data = {"url": f"{url}", "visibility": "public"}

    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        uuid = response.json()['uuid']
        logger.info(f'Запрос отправлен, UUID: {uuid}')
    except Exception as e:
        logger.error(f'Ошибка при отправке запроса: {e}')
        return

    try:
        response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/', headers=headers)
        while response.status_code == 404:
            time.sleep(2)
            response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/', headers=headers)

        result = response.json()["verdicts"]["overall"]["malicious"]
        logger.info(f'Результат анализа для {url}: malicious={result}')
        print(result)
    except Exception as e:
        logger.error(f'Ошибка при получении результата: {e}')
