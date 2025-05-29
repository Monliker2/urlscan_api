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
logger.propagate = False  # Отключает дублирование логов

# Отправка в syslog
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(asctime)s %(name)s: %(levelname)s %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

# Для отладки, вывод в консоль тоже (можно убрать, если не нужно)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger.info("Скрипт запущен")

# Загрузка API-ключа
load_dotenv()
API = getenv('API')

if not API:
    logger.error("API ключ не найден в .env")
    sys.exit(1)

def main(url):
    logger.info(f"main() вызван с URL: {url}")
    headers = {'API-Key': API, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}

    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        response.raise_for_status()  # добавим проверку успешности запроса
        uuid = response.json().get('uuid')
        if not uuid:
            logger.error("UUID не получен из ответа API")
            return
        logger.info(f'Запрос отправлен, UUID: {uuid}')
    except Exception as e:
        logger.error(f'Ошибка при отправке запроса: {e}')
        return

    try:
        # Подождём, пока результат будет готов
        for _ in range(30):  # максимум 30 попыток = 60 секунд ожидания
            response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}/', headers=headers)
            if response.status_code == 200:
                break
            elif response.status_code == 404:
                time.sleep(2)
            else:
                logger.error(f'Неожиданный статус-код {response.status_code} при запросе результата')
                return
        else:
            logger.error("Результат анализа не готов в течение 60 секунд")
            return

        result = response.json().get("verdicts", {}).get("overall", {}).get("malicious")
        logger.info(f'Результат анализа для {url}: malicious={result}')
        print(result)
    except Exception as e:
        logger.error(f'Ошибка при получении результата: {e}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.error("Использование: python script.py <url>")
        sys.exit(1)

    main(sys.argv[1])
