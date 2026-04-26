import socket
import sys
import argparse
import threading
from datetime import datetime
import ssl
import json
import paho.mqtt.client as mqtt

class MQTTSecurityAnalyzer:
    def __init__(self, target, port=1883, timeout=3):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.results = {
            'ip': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'info': [],
            'security_score': 100,
            'grade': 'N/A - Not Accessible',
            'accessible': False,
            'is_mqtt': False
        }


    def check_port_open(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except Exception:
            return False


    def is_mqtt_broker(self):
        import time
        connected = False
        connack_received = False


        def on_connect(client, userdata, flags, rc, reason=None):
            nonlocal connected, connack_received
            connack_received = True
            if rc is not None:
                connected = True
            client.disconnect()

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.on_connect = on_connect

        try:
            if self.port == 8883:
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                client.tls_insecure_set(True)

            client.connect(self.target, self.port, self.timeout)
            client.loop_start()
            wait_time = 0

            while wait_time < self.timeout and not connack_received:
                time.sleep(0.1)
                wait_time += 0.1

            client.loop_stop()

            if connected:
                self.results['info'].append({
                    'name': 'MQTT_PROTOCOL_DETECTED',
                    'description': 'Service confirmed as MQTT broker'
                })
                return True
            return False

        except Exception:
            return False


    def check_authentication_required(self):
        def on_connect(client, userdata, flags, rc, reason=None):
            """Callback при подключении — сохраняем код возврата"""
            client.userdata['rc'] = rc
            client.disconnect()

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.userdata = {'rc': None}
        client.on_connect = on_connect

        try:
            client.connect(self.target, self.port, self.timeout)
            client.loop_start()

            import time
            time.sleep(2)

            client.loop_stop()

            rc = client.userdata.get('rc')

            if rc == 0:
                self.results['vulnerabilities'].append({
                    'name': 'NO_AUTHENTICATION',
                    'severity': 'CRITICAL',
                    'description': 'Broker accepts connections without username/password',
                    'fix': 'Enable authentication in broker configuration'
                })
                self.results['security_score'] -= 40
                return False

            elif rc == 4 or rc == 5:
                self.results['info'].append({
                    'name': 'AUTHENTICATION_REQUIRED',
                    'description': f'Broker requires authentication (response code: {rc})'
                })
                return True

            else:
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


    def check_default_credentials(self):
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


    def check_tls_support(self, tls_port=8883):
        try:
            context = ssl.create_default_context()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            tls_sock = context.wrap_socket(sock, server_hostname=self.target)

            tls_sock.connect((self.target, tls_port))

            cert = tls_sock.getpeercert()
            tls_sock.close()

            if cert:
                self.results['info'].append({
                    'name': 'TLS_AVAILABLE',
                    'description': f'TLS encryption available on port {tls_port}'
                })

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
            if self.port == 1883:
                self.results['vulnerabilities'].append({
                    'name': 'NO_ENCRYPTION',
                    'severity': 'HIGH',
                    'description': 'Broker does not support TLS encryption on any port',
                    'fix': 'Configure TLS certificates and enable encrypted communication'
                })
                self.results['security_score'] -= 30
            return False


    def check_wildcard_subscription(self):
        def on_connect(client, userdata, flags, rc, reason=None):
            if rc == 0:
                client.subscribe("#", qos=0)
                client.userdata['subscribed'] = True

        def on_subscribe(client, userdata, mid, granted_qos, reason=None):
            client.userdata['subscribed_ok'] = True
            client.disconnect()

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


    def check_system_topic_access(self):
        def on_connect(client, userdata, flags, rc, reason=None):
            """При успешном подключении подписываемся на системные топики"""
            if rc == 0:
                client.subscribe("$SYS/#", qos=0)
                client.userdata['subscribed'] = True

        def on_subscribe(client, userdata, mid, granted_qos, reason=None):
            client.userdata['subscribed_ok'] = True
            client.disconnect()

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


    def run_checks(self):
        print(f"\n[*] Analyzing: {self.target}:{self.port}")
        print(f"[*] Timeout: {self.timeout}s")

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

        score = self.results['security_score']
        if score >= 80:
            grade = "A - Secure"
        elif score >= 60:
            grade = "B - Medium Risk"
        elif score >= 40:
            grade = "C - High Risk"
        else:
            grade = "F - Critical Risk"

        self.results['grade'] = grade
        self.results['security_score'] = max(0, score)

        return self.results


    def print_report(self):
        if not self.results:
            return

        print(f"\n{'=' * 60}")
        print(f"MQTT SECURITY ANALYSIS REPORT")
        print(f"{'=' * 60}")
        print(f"Target:     {self.results['ip']}:{self.results['port']}")
        print(f"Timestamp:  {self.results['timestamp']}")
        print(f"{'-' * 60}")
        print(f"Security Score: {self.results['security_score']}/100")
        print(f"Security Grade: {self.results['grade']}")
        print(f"{'-' * 60}")

        if not self.results.get('accessible', True) and self.results['security_score'] == 0:
            print(f"\n[!] BROKER NOT ACCESSIBLE")
            for info in self.results['info']:
                if info['name'] == 'BROKER_NOT_ACCESSIBLE':
                    print(f"    -> {info['description']}")
            print(f"\n{'=' * 60}\n")
            return

        if not self.results.get('is_mqtt', True) and self.results['grade'] == "N/A - Not MQTT":
            print(f"\n[!] NOT AN MQTT SERVICE")
            for info in self.results['info']:
                if info['name'] == 'NOT_MQTT_SERVICE':
                    print(f"    -> {info['description']}")
            print(f"\n{'=' * 60}\n")
            return

        if self.results['vulnerabilities']:
            print(f"\n[!] VULNERABILITIES FOUND:")
            for vuln in self.results['vulnerabilities']:
                print(f"\n  [{vuln['severity']}] {vuln['name']}")
                print(f"    -> {vuln['description']}")
                print(f"    -> Fix: {vuln['fix']}")
        else:
            print(f"\n[+] No vulnerabilities detected!")

        if self.results['info']:
            print(f"\n[*] Additional Information:")
            for info in self.results['info']:
                print(f"    -> {info['name']}: {info['description']}")

        print(f"\n{'=' * 60}\n")


    def export_json(self, filename=None):
        if filename is None:
            safe_target = self.target.replace('/', '_').replace(':', '_')
            filename = f"mqtt_report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"[+] Report saved to: {filename}")
        return filename



class NetworkScanner:
    @staticmethod
    def scan_subnet(subnet, port=1883, max_threads=50):
        results = []

        def scan_ip(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    print(f"[+] Found open port: {ip}:{port}")
                    results.append(ip)
            except Exception:
                pass

        if '/' in subnet:
            base_ip = '.'.join(subnet.split('.')[:3])
        else:
            base_ip = '.'.join(subnet.split('.')[:3])

        threads = []
        print(f"[*] Scanning {base_ip}.0/24 for open ports on port {port}...")

        for i in range(1, 255):
            ip = f"{base_ip}.{i}"

            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
            threads.append(thread)

            if len(threads) >= max_threads:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        return results


def main():

    parser = argparse.ArgumentParser(
        description='MQTT Security Analyzer - IoT Network Scanner'
    )

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

    args = parser.parse_args()

    print(f"""
    ============================================
        MQTT Security Analyzer v1.0
        IoT Network Security Tool
        Author: Korop Andrey, KZI-252
    ============================================
    """)

    if not args.target and not args.scan:
        parser.print_help()
        sys.exit(1)

    if args.scan:
        open_ports = NetworkScanner.scan_subnet(args.scan, args.port)

        if not open_ports:
            print(f"[-] No open ports found on {args.scan}")
            sys.exit(0)

        print(f"\n[+] Found {len(open_ports)} host(s) with open port {args.port}")

        all_reports = []
        for host_ip in open_ports:
            analyzer = MQTTSecurityAnalyzer(host_ip, args.port, args.timeout)
            results = analyzer.run_checks()
            analyzer.print_report()
            if args.json:
                all_reports.append(results)

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

    elif args.target:
        analyzer = MQTTSecurityAnalyzer(args.target, args.port, args.timeout)
        results = analyzer.run_checks()
        analyzer.print_report()

        if args.json:
            analyzer.export_json()



if __name__ == "__main__":
    main()
