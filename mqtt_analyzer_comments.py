#!/usr/bin/env python3
"""
================================================================================
MQTT Security Analyzer for IoT Networks
================================================================================
Автор:          Короп Андрей Юрьевич, КЗИ-252
Название:       Анализатор безопасности MQTT-брокеров в IoT-сетях
Описание:       Инструмент для сканирования сети, обнаружения MQTT-брокеров
                и проверки их конфигурации на наличие уязвимостей.

Назначение программы:
    1. Обнаруживает MQTT-брокеры в заданной сети или по конкретному IP/домену
    2. Проверяет безопасность конфигурации брокера:
        - Требуется ли аутентификация (логин/пароль)
        - Использует ли брокер стандартные/слабые пароли
        - Поддерживает ли шифрование TLS
        - Разрешена ли wildcard-подписка (#) — доступ ко ВСЕМ сообщениям
        - Доступны ли системные топики ($SYS/#) — утечка служебной информации
    3. Выдаёт отчёт с оценкой безопасности (Score 0-100) и рекомендациями

Ключевые понятия MQTT для понимания кода:
    - Брокер (Broker)   = сервер, который принимает и пересылает сообщения
    - Топик (Topic)     = адрес, на который публикуются сообщения
    - Подписка          = получение сообщений с определённого топика
    - Wildcard #        = подписка на ВСЕ топики (очень опасно!)
    - TLS/SSL           = шифрование передачи данных
================================================================================
"""

# БЛОК 1: ИМПОРТ НЕОБХОДИМЫХ МОДУЛЕЙ (БИБЛИОТЕК)

import socket
"""
Модуль socket — для низкоуровневой сетевой работы.
Используется для:
    - Проверки открытых портов (TCP-соединения)
    - Сканирования сети (подключение к IP-адресам)
"""

import sys
"""
Модуль sys — системные функции.
Используется для:
    - Выхода из программы (sys.exit())
    - Работы с аргументами командной строки (sys.argv)
"""

import argparse
"""
Модуль argparse — парсинг аргументов командной строки.
Позволяет обрабатывать флаги --target, --scan, --port, --timeout, --json.
"""

import threading
"""
Модуль threading — многопоточное программирование.
Используется в сканере сети для одновременной проверки нескольких IP-адресов.
"""

from datetime import datetime
"""
Импорт datetime — работа с датой и временем.
Используется для:
    - Фиксации времени сканирования (timestamp в отчёте)
    - Генерации уникальных имён для JSON-файлов
"""

import ssl
"""
Модуль ssl — проверка шифрования (TLS/SSL).
Используется для:
    - Попытки установить защищённое соединение на порт 8883
    - Проверки наличия SSL-сертификата у брокера
"""

import json
"""
Модуль json — экспорт результатов в формат JSON.
Позволяет сохранить отчёт в структурированном виде для дальнейшего анализа.
"""

import paho.mqtt.client as mqtt
"""
Библиотека paho-mqtt — официальный MQTT-клиент для Python.
Выполняет всю работу по общению с MQTT-брокером:
    - Установка соединения
    - Подписка на топики
    - Проверка аутентификации
    - Отправка сообщений
"""


# БЛОК 2: КЛАСС АНАЛИЗАТОРА MQTT-БРОКЕРА

class MQTTSecurityAnalyzer:
    """
    Основной класс программы.
    Содержит все методы для проверки безопасности одного MQTT-брокера.

    Что делает этот класс:
        1. Проверяет доступность порта
        2. Определяет, является ли сервис MQTT-брокером
        3. Выполняет 5 проверок безопасности
        4. Формирует отчёт с оценкой

    Атрибуты класса:
        self.target(str): IP-адрес или домен брокера
        self.port(int): Номер порта (обычно 1883 или 8883)
        self.timeout(int): Таймаут подключения в секундах
        self.results(dict): Словарь для хранения результатов анализа
    """

    def __init__(self, target, port=1883, timeout=3):
        """
        Конструктор класса. Вызывается при создании объекта.
        Инициализирует все поля и структуру для хранения результатов.

        Параметры:
            target(str): IP-адрес или домен (например "192.168.1.41")
            port(int): Порт брокера (по умолчанию 1883)
            timeout(int): Таймаут подключения (по умолчанию 3 секунды)

        Что происходит в конструкторе:
            1. Сохраняются переданные параметры
            2. Создаётся словарь results для хранения результатов
            3. Задаются начальные значения (security_score = 100)
        """
        # Сохраняем параметры в атрибуты объекта (self.)
        self.target = target          # Целевой адрес (IP или домен)
        self.port = port              # Номер порта
        self.timeout = timeout        # Таймаут подключения

        # Словарь результатов — сюда будем записывать всё, что найдём
        self.results = {
            'ip': target,             # Целевой адрес
            'port': port,             # Целевой порт
            'timestamp': datetime.now().isoformat(),  # Время начала проверки (ISO формат)
            'vulnerabilities': [],    # Список найденных уязвимостей
            'info': [],               # Список информационных сообщений
            'security_score': 100,    # Начальная оценка безопасности (100 = идеально)
            'grade': 'N/A - Not Accessible',  # Итоговая оценка (A, B, C, F)
            'accessible': False,      # Флаг: доступен ли брокер
            'is_mqtt': False          # Флаг: является ли сервис MQTT
        }

    # МЕТОД 1: ПРОВЕРКА ОТКРЫТОГО ПОРТА

    def check_port_open(self):
        """
        Проверяет, открыт ли указанный порт на целевом хосте.

        Принцип работы:
            1. Создаётся TCP-сокет (низкоуровневое соединение)
            2. Выполняется попытка подключения к IP:PORT
            3. Если connect_ex() вернул 0 → порт открыт
            4. Если ошибка или таймаут → порт закрыт

        Возвращает:
            True — порт открыт, брокер доступен
            False — порт закрыт или хост не отвечает
        """
        try:
            # Создаём TCP-сокет (AF_INET → IPv4, SOCK_STREAM → TCP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Устанавливаем таймаут — если ответа нет дольше, считаем порт закрытым
            sock.settimeout(self.timeout)

            # connect_ex() возвращает 0 при успешном подключении
            result = sock.connect_ex((self.target, self.port))

            # Закрываем сокет
            sock.close()

            # Если result == 0, подключение успешно → порт открыт
            return result == 0

        except Exception:
            # Любая ошибка → порт закрыт
            return False

    # МЕТОД 2: ОПРЕДЕЛЕНИЕ MQTT-БРОКЕРА (НЕ HTTP, НЕ SSH И Т.Д.)

    def is_mqtt_broker(self):
        """
        Проверяет, является ли сервис на указанном порту MQTT-брокером.

        Принцип работы:
            1. Пытаемся подключиться к брокеру через библиотеку paho-mqtt
            2. Библиотека автоматически отправляет CONNECT пакет
            3. Если брокер отвечает CONNACK (любой код ответа) — это MQTT
            4. Если нет ответа или ошибка — это НЕ MQTT

        Возвращает:
            True — это MQTT-брокер
            False — это НЕ MQTT-брокер
        """
        import time  # Импортируем time для задержек

        # Флаги для отслеживания состояния подключения
        connected = False           # Был ли получен ответ от брокера?
        connack_received = False    # Был ли получен CONNACK пакет?

        def on_connect(client, userdata, flags, rc, reason=None):
            """
            Callback-функция (обратный вызов). Вызывается автоматически,
            когда брокер отвечает на CONNECT запрос.

            Параметры:
                client — объект MQTT-клиента
                userdata — пользовательские данные
                flags — флаги подключения
                rc — код возврата (0 = успех, 1-5 = ошибки)
                reason — причина (для новой версии API)

            Коды возврата (rc):
                0 — успешное подключение
                1 — неподдерживаемая версия протокола
                2 — недопустимый идентификатор клиента
                3 — сервер недоступен
                4 — неверный логин/пароль
                5 — не авторизован

            ЛЮБОЙ код ответа означает, что на том конце MQTT-брокер!
            """
            nonlocal connected, connack_received
            connack_received = True   # Мы получили ответ от брокера
            if rc is not None:
                connected = True      # Брокер ответил — значит это MQTT
            client.disconnect()       # Отключаемся, проверка завершена

        # Создаём MQTT-клиента
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

        # Назначаем callback-функцию на событие подключения
        client.on_connect = on_connect

        try:
            # Если используется порт TLS (8883) — настраиваем шифрование
            if self.port == 8883:
                # Включаем TLS/SSL для соединения
                # CERT_NONE — не проверяем сертификат (для тестирования)
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                # Разрешаем соединение с неподтверждённым сертификатом
                client.tls_insecure_set(True)

            # Пытаемся подключиться к брокеру
            client.connect(self.target, self.port, self.timeout)

            # Запускаем сетевой цикл в отдельном потоке
            client.loop_start()

            # Ждём ответа от брокера (максимум self.timeout секунд)
            wait_time = 0
            while wait_time < self.timeout and not connack_received:
                time.sleep(0.1)      # Проверяем каждые 0.1 секунды
                wait_time += 0.1

            # Останавливаем сетевой цикл
            client.loop_stop()

            # Если получили ответ — это MQTT-брокер
            if connected:
                self.results['info'].append({
                    'name': 'MQTT_PROTOCOL_DETECTED',
                    'description': 'Service confirmed as MQTT broker'
                })
                return True
            return False

        except Exception:
            # Исключение — скорее всего не MQTT
            return False

    # МЕТОД 3: ПРОВЕРКА АУТЕНТИФИКАЦИИ

    def check_authentication_required(self):
        """
        Проверяет, требует ли брокер авторизации.

        Важно: анализирует КОД ВОЗВРАТА (rc), а не просто факт вызова callback.

        Коды возврата MQTT (rc):
            0 — успешное подключение (НЕТ АУТЕНТИФИКАЦИИ — УЯЗВИМОСТЬ!)
            1 — неподдерживаемая версия протокола
            2 — недопустимый ID клиента
            3 — сервер недоступен
            4 — неверный логин/пароль (АУТЕНТИФИКАЦИЯ ЕСТЬ — ХОРОШО)
            5 — не авторизован (АУТЕНТИФИКАЦИЯ ЕСТЬ — ХОРОШО)
        """

        def on_connect(client, userdata, flags, rc, reason=None):
            """Callback при подключении — сохраняем код возврата"""
            client.userdata['rc'] = rc  # Сохраняем код возврата
            client.disconnect()

        # Создаём клиента
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.userdata = {'rc': None}  # Хранилище для кода возврата
        client.on_connect = on_connect

        try:
            # Подключаемся БЕЗ логина и пароля
            client.connect(self.target, self.port, self.timeout)
            client.loop_start()

            import time
            time.sleep(2)

            client.loop_stop()

            rc = client.userdata.get('rc')

            # Анализируем код возврата
            if rc == 0:
                # Подключение успешно без пароля → КРИТИЧЕСКАЯ УЯЗВИМОСТЬ
                self.results['vulnerabilities'].append({
                    'name': 'NO_AUTHENTICATION',
                    'severity': 'CRITICAL',
                    'description': 'Broker accepts connections without username/password',
                    'fix': 'Enable authentication in broker configuration'
                })
                self.results['security_score'] -= 40
                return False

            elif rc == 4 or rc == 5:
                # Брокер требует аутентификацию (rc=4 или rc=5) → ЭТО ХОРОШО!
                self.results['info'].append({
                    'name': 'AUTHENTICATION_REQUIRED',
                    'description': f'Broker requires authentication (response code: {rc})'
                })
                return True

            else:
                # Другой код возврата — не можем определить
                self.results['info'].append({
                    'name': 'AUTH_CHECK_UNKNOWN',
                    'description': f'Unexpected response code: {rc}'
                })
                return None

        except Exception as e:
            self.results['info'].append({
                'name': 'AUTH_CHECK_FAILED',
                'description': f'Could not determine auth status: {str(e)}'
            })
            return None

    # МЕТОД 4: ПРОВЕРКА СТАНДАРТНЫХ ПАРОЛЕЙ

    def check_default_credentials(self):
        """Проверяет стандартные пароли."""
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('guest', 'guest'),
            ('mqtt', 'mqtt'),
            ('user', 'user'),
            ('test', 'test'),
            ('broker', 'broker'),
            ('', ''),
        ]

        found_creds = []

        for username, password in default_creds:
            def on_connect(client, userdata, flags, rc, reason=None):
                # Сохраняем код возврата в userdata
                client.userdata['rc'] = rc
                client.disconnect()

            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            client.userdata = {'rc': None}
            client.on_connect = on_connect

            if username:
                client.username_pw_set(username, password)

            try:
                client.connect(self.target, self.port, self.timeout)
                client.loop_start()

                import time
                time.sleep(1.5)

                client.loop_stop()

                # Успех только если rc == 0
                if client.userdata.get('rc') == 0:
                    found_creds.append(f"{username}:{password}")
            except:
                pass

        if found_creds:
            self.results['vulnerabilities'].append({
                'name': 'DEFAULT_CREDENTIALS',
                'severity': 'CRITICAL',
                'description': f'Broker accepts default/weak credentials: {", ".join(found_creds)}',
                'fix': 'Change all default passwords immediately to strong unique passwords'
            })
            self.results['security_score'] -= 35
            return found_creds
        return None

    # МЕТОД 5: ПРОВЕРКА ПОДДЕРЖКИ ШИФРОВАНИЯ (TLS)

    def check_tls_support(self, tls_port=8883):
        """
        Проверяет, поддерживает ли брокер шифрование TLS.

        Параметры:
            tls_port(int): порт для TLS-соединения (по умолчанию 8883)

        Принцип работы:
            1. Пытаемся установить защищённое SSL/TLS-соединение на порт 8883
            2. Если получаем сертификат — TLS поддерживается
            3. Если нет — шифрование отсутствует

        """
        try:
            # Создаём контекст SSL с настройками по умолчанию
            context = ssl.create_default_context()

            # Обычный TCP-сокет
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Оборачиваем сокет в SSL (создаём защищённое соединение)
            tls_sock = context.wrap_socket(sock, server_hostname=self.target)

            # Подключаемся к порту TLS
            tls_sock.connect((self.target, tls_port))

            # Получаем сертификат (информация о шифровании)
            cert = tls_sock.getpeercert()
            tls_sock.close()

            # Если сертификат получен — TLS поддерживается
            if cert:
                self.results['info'].append({
                    'name': 'TLS_AVAILABLE',
                    'description': f'TLS encryption available on port {tls_port}'
                })

                # Если основной порт 1883, а TLS на 8883 — предупреждение
                if self.port == 1883:
                    self.results['vulnerabilities'].append({
                        'name': 'NO_TLS_ON_DEFAULT_PORT',
                        'severity': 'MEDIUM',
                        'description': f'Broker does NOT use TLS on port {self.port} (but supports on {tls_port})',
                        'fix': 'Enable TLS on default port 1883 or enforce TLS-only connections'
                    })
                    self.results['security_score'] -= 15
                return True

        except Exception:
            # TLS не поддерживается — уязвимость
            if self.port == 1883:
                self.results['vulnerabilities'].append({
                    'name': 'NO_ENCRYPTION',
                    'severity': 'HIGH',
                    'description': 'Broker does not support TLS encryption on any port',
                    'fix': 'Configure TLS certificates and enable encrypted communication'
                })
                self.results['security_score'] -= 30
            return False

    # МЕТОД 6: ПРОВЕРКА WILDCARD-ПОДПИСКИ (#)

    def check_wildcard_subscription(self):
        """
        Проверяет, разрешает ли брокер wildcard-подписку с символом '#'.

        Что такое wildcard '#'?
            Это символ, который означает "все топики".
            Подписка на "#" даёт доступ к АБСОЛЮТНО ВСЕМ сообщениям брокера.

        Почему это опасно:
            Если злоумышленник может подписаться на "#", он будет:
                - Читать показания всех датчиков
                - Видеть видео с камер
                - Перехватывать команды управления

        Принцип работы:
            1. Подключаемся к брокеру
            2. Пытаемся подписаться на топик "#"
            3. Если подписка успешна — найдена уязвимость!
        """
        def on_connect(client, userdata, flags, rc, reason=None):
            """При успешном подключении подписываемся на #"""
            if rc == 0:
                client.subscribe("#", qos=0)  # # = все топики
                client.userdata['subscribed'] = True

        def on_subscribe(client, userdata, mid, granted_qos, reason=None):
            """Callback при успешной подписке"""
            client.userdata['subscribed_ok'] = True
            client.disconnect()

        # Создаём клиента
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.userdata = {'subscribed': False, 'subscribed_ok': False}
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe

        try:
            client.connect(self.target, self.port, self.timeout)
            client.loop_start()

            import time
            time.sleep(3)  # Ждём ответа

            # Если подписка успешна — уязвимость
            if client.userdata.get('subscribed_ok', False):
                self.results['vulnerabilities'].append({
                    'name': 'WILDCARD_SUBSCRIPTION_ALLOWED',
                    'severity': 'HIGH',
                    'description': 'Broker allows wildcard subscription (#) - attacker can read ALL messages',
                    'fix': 'Configure ACL (Access Control List) to restrict topic access'
                })
                self.results['security_score'] -= 25
                return True
            else:
                self.results['info'].append({
                    'name': 'WILDCARD_BLOCKED',
                    'description': 'Wildcard subscription appears to be restricted'
                })
                return False
        except Exception:
            return None

    # МЕТОД 7: ПРОВЕРКА ДОСТУПА К СИСТЕМНЫМ ТОПИКАМ ($SYS/#)

    def check_system_topic_access(self):
        """
        Проверяет, доступны ли системные топики ($SYS/#).

        Что такое $SYS топики?
            Это служебные топики, которые содержат информацию о самом брокере:
                - Версия брокера
                - Количество подключений
                - Статистика сообщений
                - Информация о клиентах

        Почему это опасно:
            Злоумышленник может узнать:
                - Версию брокера (для подбора эксплойтов)
                - Масштаб системы
                - Слабые места в конфигурации
        """
        def on_connect(client, userdata, flags, rc, reason=None):
            """При успешном подключении подписываемся на системные топики"""
            if rc == 0:
                client.subscribe("$SYS/#", qos=0)
                client.userdata['subscribed'] = True

        def on_subscribe(client, userdata, mid, granted_qos, reason=None):
            client.userdata['subscribed_ok'] = True
            client.disconnect()

        # Создаём клиента
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.userdata = {'subscribed': False, 'subscribed_ok': False}
        client.on_connect = on_connect
        client.on_subscribe = on_subscribe

        try:
            client.connect(self.target, self.port, self.timeout)
            client.loop_start()

            import time
            time.sleep(3)

            if client.userdata.get('subscribed_ok', False):
                self.results['vulnerabilities'].append({
                    'name': 'SYSTEM_TOPIC_EXPOSED',
                    'severity': 'MEDIUM',
                    'description': 'Broker exposes $SYS topics - leaks broker statistics and information',
                    'fix': 'Restrict access to $SYS topics in broker configuration'
                })
                self.results['security_score'] -= 10
                return True
            return False
        except Exception:
            return None

    # МЕТОД 8: ЗАПУСК ВСЕХ ПРОВЕРОК (ГЛАВНЫЙ МЕТОД)

    def run_checks(self):
        """
        Главный метод, который запускает все проверки по порядку.

        Порядок выполнения:
            1. Проверка открытости порта
            2. Определение MQTT-протокола
            3. Проверка аутентификации
            4. Проверка стандартных паролей
            5. Проверка TLS/шифрования
            6. Проверка wildcard-подписки
            7. Проверка системных топиков
            8. Расчёт итоговой оценки безопасности

        Возвращает:
            self.results — словарь со всеми результатами
        """
        print(f"\n[*] Analyzing: {self.target}:{self.port}")
        print(f"[*] Timeout: {self.timeout}s")

        # ШАГ 1: Проверка доступности порта
        if not self.check_port_open():
            print(f"[-] Port {self.port} is closed or unreachable")
            self.results['accessible'] = False
            self.results['security_score'] = 0
            self.results['grade'] = "F - Not Accessible"
            self.results['info'].append({
                'name': 'BROKER_NOT_ACCESSIBLE',
                'description': f'Could not reach {self.target}:{self.port}'
            })
            return self.results

        print(f"[+] Port {self.port} is open")

        # ШАГ 2: Определение MQTT-протокола
        print("[*] Detecting MQTT protocol...")
        if not self.is_mqtt_broker():
            print(f"[-] Service on port {self.port} is NOT an MQTT broker")
            self.results['accessible'] = True
            self.results['is_mqtt'] = False
            self.results['security_score'] = 0
            self.results['grade'] = "N/A - Not MQTT"
            self.results['info'].append({
                'name': 'NOT_MQTT_SERVICE',
                'description': f'Port {self.port} is open but does not respond to MQTT protocol'
            })
            return self.results

        print(f"[+] MQTT broker confirmed")
        self.results['accessible'] = True
        self.results['is_mqtt'] = True

        # ШАГ 3-7: Запуск всех проверок безопасности
        print("[*] Checking authentication requirement...")
        self.check_authentication_required()

        print("[*] Testing default credentials...")
        self.check_default_credentials()

        print("[*] Checking TLS/encryption...")
        self.check_tls_support()

        print("[*] Testing wildcard subscription (#)...")
        self.check_wildcard_subscription()

        print("[*] Checking system topic access ($SYS/#)...")
        self.check_system_topic_access()

        # ШАГ 8: Расчёт итоговой оценки
        score = self.results['security_score']
        if score >= 80:
            grade = "A - Secure"          # Отлично — нет уязвимостей
        elif score >= 60:
            grade = "B - Medium Risk"     # Средний риск — есть пара проблем
        elif score >= 40:
            grade = "C - High Risk"       # Высокий риск — много уязвимостей
        else:
            grade = "F - Critical Risk"   # Критический риск — брокер опасен

        self.results['grade'] = grade
        self.results['security_score'] = max(0, score)  # Оценка не может быть ниже 0

        return self.results

    # МЕТОД 9: ВЫВОД ОТЧЁТА НА ЭКРАН

    def print_report(self):
        """
        Выводит отформатированный отчёт о безопасности в консоль.

        Формат отчёта:
            - Заголовок с информацией о цели
            - Оценка безопасности (0-100) и уровень (A, B, C, F)
            - Список найденных уязвимостей (если есть)
            - Рекомендации по исправлению
            - Дополнительная информация
        """
        if not self.results:
            return

        # Разделительная линия (60 символов =)
        print(f"\n{'=' * 60}")
        print(f"MQTT SECURITY ANALYSIS REPORT")
        print(f"{'=' * 60}")
        print(f"Target:     {self.results['ip']}:{self.results['port']}")
        print(f"Timestamp:  {self.results['timestamp']}")
        print(f"{'-' * 60}")
        print(f"Security Score: {self.results['security_score']}/100")
        print(f"Security Grade: {self.results['grade']}")
        print(f"{'-' * 60}")

        # СЛУЧАЙ 1: Брокер недоступен
        if not self.results.get('accessible', True) and self.results['security_score'] == 0:
            print(f"\n[!] BROKER NOT ACCESSIBLE")
            for info in self.results['info']:
                if info['name'] == 'BROKER_NOT_ACCESSIBLE':
                    print(f"    -> {info['description']}")
            print(f"\n{'=' * 60}\n")
            return

        # СЛУЧАЙ 2: Это не MQTT сервис
        if not self.results.get('is_mqtt', True) and self.results['grade'] == "N/A - Not MQTT":
            print(f"\n[!] NOT AN MQTT SERVICE")
            for info in self.results['info']:
                if info['name'] == 'NOT_MQTT_SERVICE':
                    print(f"    -> {info['description']}")
            print(f"\n{'=' * 60}\n")
            return

        # СЛУЧАЙ 3: MQTT брокер — выводим уязвимости
        if self.results['vulnerabilities']:
            print(f"\n[!] VULNERABILITIES FOUND:")
            for vuln in self.results['vulnerabilities']:
                print(f"\n  [{vuln['severity']}] {vuln['name']}")
                print(f"    -> {vuln['description']}")
                print(f"    -> Fix: {vuln['fix']}")
        else:
            print(f"\n[+] No vulnerabilities detected!")

        # Выводим дополнительную информацию
        if self.results['info']:
            print(f"\n[*] Additional Information:")
            for info in self.results['info']:
                print(f"    -> {info['name']}: {info['description']}")

        print(f"\n{'=' * 60}\n")

    # МЕТОД 10: ЭКСПОРТ РЕЗУЛЬТАТОВ В JSON-ФАЙЛ

    def export_json(self, filename=None):
        """
        Сохраняет результаты анализа в JSON-файл.

        Зачем это нужно:
            - Можно импортировать в другие программы
            - Удобно для автоматизации
            - Хорошо для документации

        Параметры:
            filename(str): имя файла (если не указано — генерируется)

        Возвращает:
            filename(str): имя сохранённого файла
        """
        if filename is None:
            # Генерируем имя: mqtt_report_IP_дата_время.json
            safe_target = self.target.replace('/', '_').replace(':', '_')
            filename = f"mqtt_report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Открываем файл и сохраняем JSON (indent=2 для читаемости)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"[+] Report saved to: {filename}")
        return filename


# БЛОК 3: КЛАСС СЕТЕВОГО СКАНЕРА

class NetworkScanner:
    """
    Класс для сканирования локальной сети и поиска MQTT-брокеров.

    Принцип работы:
        1. Перебирает все IP-адреса в заданной подсети (от 1 до 254)
        2. Для каждого IP проверяет, открыт ли порт 1883 (или указанный)
        3. Использует многопоточность для ускорения сканирования
        4. Возвращает список IP-адресов с открытыми портами

    Зачем это нужно:
        Администратор может быстро найти все MQTT-устройства в своей сети.
    """

    @staticmethod
    def scan_subnet(subnet, port=1883, max_threads=50):
        """
        Сканирует подсеть /24 на наличие открытых портов.

        Параметры:
            subnet(str): подсеть (например "192.168.1.0/24")
            port(int): порт для сканирования (по умолчанию 1883)
            max_threads(int): максимальное количество потоков

        Возвращает:
            list: IP-адреса с открытым портом
        """
        results = []  # Список найденных адресов

        def scan_ip(ip):
            """
            Внутренняя функция для сканирования одного IP.
            Запускается в отдельном потоке для каждого адреса.
            """
            try:
                # Создаём сокет для проверки порта
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Таймаут 1 секунда (быстрое сканирование)
                result = sock.connect_ex((ip, port))
                sock.close()

                # Если порт открыт — добавляем в результаты
                if result == 0:
                    print(f"[+] Found open port: {ip}:{port}")
                    results.append(ip)
            except Exception:
                pass  # Игнорируем ошибки (недоступные хосты)

        # Извлекаем базовый IP из подсети (первые 3 октета)
        # Например "192.168.1.0/24" → "192.168.1"
        if '/' in subnet:
            base_ip = '.'.join(subnet.split('.')[:3])
        else:
            base_ip = '.'.join(subnet.split('.')[:3])

        threads = []  # Список запущенных потоков
        print(f"[*] Scanning {base_ip}.0/24 for open ports on port {port}...")

        # Перебираем адреса от 1 до 254 (.0 — адрес сети, .255 — широковещательный)
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"

            # Создаём поток для сканирования этого IP
            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
            threads.append(thread)

            # Если достигли лимита потоков — ждём их завершения
            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []

        # Ждём завершения оставшихся потоков
        for t in threads:
            t.join()

        return results


# БЛОК 4: ГЛАВНАЯ ФУНКЦИЯ (ТОЧКА ВХОДА В ПРОГРАММУ)

def main():
    """
    Главная функция программы.

    Что делает:
        1. Обрабатывает аргументы командной строки (--target, --scan, --port и т.д.)
        2. Запускает либо режим сканирования сети, либо режим анализа одной цели
        3. Выводит результаты и (опционально) сохраняет в JSON

    Режимы работы:
        --target IP   — проверить конкретный MQTT-брокер
        --scan  CIDR  — найти все MQTT-брокеры в подсети (например 192.168.1.0/24)
    """

    # Создаём парсер аргументов командной строки
    parser = argparse.ArgumentParser(
        description='MQTT Security Analyzer - IoT Network Scanner'
    )

    # Определяем возможные аргументы
    parser.add_argument('--target', '-t',
                        help='Single target IP address or hostname')

    parser.add_argument('--scan', '-s',
                        help='Scan subnet (e.g., 192.168.1.0/24)')

    parser.add_argument('--port', '-p', type=int, default=1883,
                        help='Port to check (default: 1883)')

    parser.add_argument('--timeout', type=int, default=3,
                        help='Connection timeout in seconds')

    parser.add_argument('--json', action='store_true',
                        help='Export results to JSON file')

    # Парсим аргументы командной строки
    args = parser.parse_args()

    # Выводим заголовок программы
    print(f"""
    ============================================
        MQTT Security Analyzer v1.0
        IoT Network Security Tool
        Author: Korop Andrey, KZI-252
    ============================================
    """)

    # Проверяем, что указан либо --target, либо --scan
    if not args.target and not args.scan:
        parser.print_help()  # Если ничего не указано — показываем справку
        sys.exit(1)

    # РЕЖИМ СКАНИРОВАНИЯ СЕТИ
    if args.scan:
        # Запускаем сканирование подсети
        open_ports = NetworkScanner.scan_subnet(args.scan, args.port)

        if not open_ports:
            print(f"[-] No open ports found on {args.scan}")
            sys.exit(0)

        print(f"\n[+] Found {len(open_ports)} host(s) with open port {args.port}")

        all_reports = []
        # Для каждого найденного хоста запускаем анализ
        for host_ip in open_ports:
            analyzer = MQTTSecurityAnalyzer(host_ip, args.port, args.timeout)
            results = analyzer.run_checks()
            analyzer.print_report()
            if args.json:
                all_reports.append(results)

        # Если нужен JSON — сохраняем общий отчёт
        if args.json and all_reports:
            combined_report = {
                'scan_target': args.scan,
                'hosts_found': len(open_ports),
                'timestamp': datetime.now().isoformat(),
                'reports': all_reports
            }
            filename = f"mqtt_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(combined_report, f, indent=2, ensure_ascii=False)
            print(f"[+] Combined report saved to: {filename}")

    # РЕЖИМ АНАЛИЗА ОДНОЙ ЦЕЛИ
    elif args.target:
        # Создаём анализатор и запускаем проверки
        analyzer = MQTTSecurityAnalyzer(args.target, args.port, args.timeout)
        results = analyzer.run_checks()
        analyzer.print_report()

        # Сохраняем JSON если нужно
        if args.json:
            analyzer.export_json()


# ТОЧКА ВХОДА В ПРОГРАММУ

if __name__ == "__main__":
    """
    Эта конструкция означает:
        "Если этот файл запущен напрямую,
         то выполнить функцию main()"

    Если файл импортирован как модуль (import mqtt_analyzer) —
    то main() не запускается автоматически.
    """
    main()