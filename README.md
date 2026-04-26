# mqtt_analyzer

Инструмент для сканирования сети и анализа безопасности MQTT-брокеров в IoT-сетях. Проверяет наличие аутентификации, стандартных паролей, поддержки TLS, wildcard-подписки (#) и доступа к системным топикам ($SYS/#).

## Требования

- __Python 3.10__ или выше
- __pip__
- Доступ в сеть к проверяемым MQTT-брокерам

## Установка

1. Клонировать репозиторий (или скачать ZIP-архив):
   ```
   git clone https://github.com/ваш-логин/mqtt-security-analyzer.git
   cd mqtt-security-analyzer
   
2. Установить зависимости:
   - Для Windows:
      ```
      ./install_paho-mqtt.bat
   - Для Linux/macOS:
      ```
      bash install_paho-mqtt.sh 
     
## Запуск
### Справка по командам
    python mqtt_analyzer.py --help

### Режим 1: Анализ одного брокера
    python mqtt_analyzer.py --target 192.168.1.100 --port 1883
    python mqtt_analyzer.py -t broker.emqx.io -p 1883

### Режим 2: Сканирование подсети /24
    python mqtt_analyzer.py --scan 192.168.1.0/24

### Сохранение отчёта в JSON
    python mqtt_analyzer.py -t 192.168.1.100 --json

### Изменение таймаута (для медленных сетей)
    python mqtt_analyzer.py -t broker.emqx.io --timeout 5
  
- Пример вывода:
    ```
    text
    ============================================================
    MQTT SECURITY ANALYSIS REPORT
    ============================================================
    Target:     192.168.1.100:1883
    Timestamp:  2026-04-26T12:00:00.123456
    ------------------------------------------------------------
    Security Score: 30/100
    Security Grade: F - Critical Risk
    ------------------------------------------------------------
    
    [!] VULNERABILITIES FOUND:
    
    [CRITICAL] NO_AUTHENTICATION
    -> Broker accepts connections without username/password
    -> Fix: Enable authentication in broker configuration
    
    [HIGH] NO_ENCRYPTION
    -> Broker does not support TLS encryption on any port
    -> Fix: Configure TLS certificates and enable encrypted communication
    
    [*] Additional Information:
    -> MQTT_PROTOCOL_DETECTED: Service confirmed as MQTT broker
    -> WILDCARD_BLOCKED: Wildcard subscription appears to be restricted
    
    ============================================================
    ```

## Что проверяет инструмент

| Проверка           | Уязвимость                          | Баллы |
|--------------------|-------------------------------------|-------|
| Аутентификация     | Нет пароля → доступ без авторизации | −40   |
| Стандартные пароли | admin/admin, guest/guest и др.      | −35   |
| Шифрование TLS     | Данные передаются в открытом виде   | −30   |
| Wildcard #         | Подписка на ВСЕ сообщения           | −25   |
| $SYS/# топики      | Утечка служебной информации         | −10   |

Оценка безопасности (Security Score):

- A (80–100) — Secure (безопасно)

- B (60–79) — Medium Risk (средний риск)

- C (40–59) — High Risk (высокий риск)

- F (0–39) — Critical Risk (критический риск)

## Возможные проблемы и решения
### Ошибка: `ModuleNotFoundError: No module named 'paho'`

Решение: установите библиотеку вручную\
    `pip install paho-mqtt`

### Ошибка: KeyError: 'grade' (старая версия)
Решение: скачайте последнюю версию из репозитория.

### Порт закрыт или брокер не отвечает
Инструмент выдаст отчёт: `F - Not Accessible`. Проверьте IP-адрес и доступность брокера в сети.

#

### Лицензия
Проект разработан в учебных целях. Свободное использование при условии указания авторства.

### Автор
Короп Андрей Юрьевич, КЗИ-252, ОмГТУ, 2026
