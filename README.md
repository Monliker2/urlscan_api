# URLScan Automation Script

Этот скрипт на Python отправляет указанный URL на сервис [urlscan.io](https://urlscan.io) для сканирования и выводит verdict о том, является ли сайт вредоносным.

## Возможности

* Читает API-ключ из файла среды (`.env`).
* Отправляет запрос на сканирование URL (`POST /api/v1/scan/`).
* Ожидает готовности результата, опрашивая API до тех пор, пока статус не станет доступным.
* Выводит финальный `malicious` verdict (`true`/`false`).

## Требования

* Python 3.7+
* Установленные зависимости:

  ```bash
  pip install requests python-dotenv
  ```

## Настройка

1. Зарегистрируйтесь на [urlscan.io](https://urlscan.io) и получите API-ключ.
2. Создайте файл `.env` в корне проекта со строкой:

   ```dotenv
   API=ваш_api_ключ
   ```

## Использование

```bash
python script.py <URL> [--timeout <секунд>]
```

* `<URL>` — адрес страницы для сканирования.
* `[--timeout <секунд>]` — (необязательно) время ожидания между попытками опроса API (по умолчанию 2 секунды).

### Пример

```bash
python script.py https://example.com
# Вывод:
# true
```

## Выходные коды

* `0` — успешное выполнение, verdict выведен в stdout.
* `1` — неверное использование (не передан URL).
