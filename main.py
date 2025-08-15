import base64
import concurrent.futures
import json
import random
import string
from datetime import datetime
from random import randint
import certifi
import httpx
import requests, os
from colorama import Fore, init
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import hashlib
from pathlib import Path
import sys
import ctypes
import pyfiglet

# Initialize colorama
init()

# Load config
config = json.load(open('config.json'))

if os.name == "nt":
    ctypes.windll.kernel32.SetConsoleTitleW(f"Password Changer")
else:
    pass

def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

os.system('cls' if os.name == 'nt' else 'clear')

changed = 0
total = len(open('input/tokens.txt').readlines())
errors  = 0
invalid = 0

def remove(file_name, line):
    with open(file_name, 'r') as f:
        lines = f.readlines()
    with open(file_name, 'w') as f:
        for i in lines:
            if i != line:
                f.write(i)
    
if not os.path.exists('input'):
    os.makedirs('input')

if not os.path.exists('output'):
    os.makedirs('output')

ORIGIN_CIPHERS = ('ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:' 'DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES')
os.system('cls' if os.name == 'nt' else 'clear')

class SSLContext(object):
    @staticmethod
    def GetContext():
        ciphers_top = "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM"
        ciphers_mid = 'DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES'
        cl = ciphers_mid.split(":")
        cl_len = len(cl)
        els = []
        
        for i in range(cl_len):
            idx = randint(0, cl_len-1)
            els.append(cl[idx])
            del cl[idx]
            cl_len-=1
        
        ciphers2 = ciphers_top+":".join(els)
        context = httpx.create_ssl_context()
        context.load_verify_locations(cafile=certifi.where())
        context.set_alpn_protocols(["h2"])
        context.minimum_version.MAXIMUM_SUPPORTED
        CIPHERS = ciphers2
        context.set_ciphers(CIPHERS)
        
        return context
    
    @staticmethod
    def GetTransport():
        return httpx.HTTPTransport(retries=3)

class DESAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        CIPHERS = ORIGIN_CIPHERS.split(':')
        random.shuffle(CIPHERS)
        CIPHERS = ':'.join(CIPHERS)
        self.CIPHERS = CIPHERS + ':!aNULL:!eNULL:!MD5'
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context(ciphers=self.CIPHERS)
        kwargs['ssl_context'] = context
        return super(DESAdapter, self).proxy_manager_for(*args, **kwargs)
    
def timestamp():
    return f"{Fore.RESET}{Fore.LIGHTMAGENTA_EX}{datetime.now().strftime('%H:%M:%S')}{Fore.RESET}"

class Console():
    @staticmethod
    def error(message):
        time = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.RESET}[{Fore.BLUE}{str(time)}{Fore.RESET}] {message}{Fore.RESET}")
    
    @staticmethod
    def info(message):
        time = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.RESET}[{Fore.BLUE}{str(time)}{Fore.RESET}] {message}{Fore.RESET}")
    
    @staticmethod
    def success(message):
        time = datetime.now().strftime("%H:%M:%S")
        print(f"{Fore.RESET}[{Fore.BLUE}{str(time)}{Fore.RESET}] {message}{Fore.RESET}")

def checkEmpty(filename): #checks if the file passed is empty or not
    mypath = Path(filename)
    return mypath.stat().st_size == 0

def get_random_string(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

class Headers():
    @staticmethod
    def get_fingerprint(client):
        try:
            fingerprint = client.get("https://discord.com/api/v9/experiments", timeout=5).json()["fingerprint"]
            return fingerprint
        except Exception as e:
            print("Error: ", e)
            return

    @staticmethod
    def get_super_properties():
        properties = '''{"os":"Windows","browser":"Chrome","device":"","system_locale":"en-GB","browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36","browser_version":"95.0.4638.54","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":102113,"client_event_source":null}'''
        properties = base64.b64encode(properties.encode()).decode()
        return properties
    
    @staticmethod
    def get_cookies(client):
        r = client.get("https://discord.com/", timeout=5)
        dcf = r.cookies.get("__dcfduid")
        sdc = r.cookies.get("__sdcfduid")
        return f'__dcfduid={dcf}; __sdcfduid={sdc}'
    
    @staticmethod
    def get_headers(client,token):
        cookies = Headers.get_cookies(client)
        fingerprint = Headers.get_fingerprint(client)
        super_properties = Headers.get_super_properties()
        headers = {
            'authority': 'discord.com',
            'method': 'POST',
            'scheme': 'https',
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'accept-language': 'en-US',
            'authorization': token,
            'cookie': cookies,
            'origin': 'https://discord.com',
            'sec-ch-ua': '"Google Chrome";v="95", "Chromium";v="95", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36',
            'x-debug-options': 'bugReporterEnabled',
            'x-fingerprint': fingerprint,
            'x-super-properties': super_properties,
        }
        return headers
    
class Sub():
    @staticmethod
    def passw():
        config= json.loads(open('config.json').read())
        if config['password'] == 'random':
            password = get_random_string(8)
            return password
        else:
            password = config['password']
            return password

class Change():
    @staticmethod
    def change_password(client, token, password):
        global invalid
        headers = Headers.get_headers(client, token)
        new_pass = Sub.passw()
        passw = password
        payload = {
            'new_password': new_pass,
            'password': passw,
        }
        r = client.patch("https://discord.com/api/v9/users/@me", headers=headers, json=payload, timeout=5)
        if r.status_code == 200:
            token = r.json()['token']
            username = r.json()['username'] + '#' + r.json()['discriminator']
            email = r.json()['email']
            Console.success(f"{Fore.GREEN}SUCCESS{Fore.RESET} | {Fore.MAGENTA}Succesfully Changed Token: {token[:39]}**** |  -> {new_pass}")
            return email, token, new_pass
        else:
            try:
                s = r.json()['message']
            except:
                s = 'Unknown Error'
            Console.error(f"{Fore.RED}ERROR{Fore.RESET} | {Fore.MAGENTA}Failed Changing Password: {token[:39]}**** Error: {s}")
            invalid += 1
            return False

def change_password_for_token(line, output_file, proxy=None):
    global changed, errors

    email, password, token = line.strip().split(':')
    try:
        client = requests.Session()
        if proxy:
            # Format the proxy for requests
            proxy_url = f"http://{proxy}"
            client.proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
        client.mount('https://', DESAdapter())
        task = Change.change_password(client, token, password)
        if task:
            email, token, new_pass = task
            output_file.write(f"{email}:{new_pass}:{token}\n")
            remove('input/tokens.txt', line=line.strip())
            changed += 1
    except Exception as e:
        Console.error(f"{Fore.RED}ERROR{Fore.RESET} | {Fore.MAGENTA}Failed Changing Password: {token[:39]}**** Error: {e}")
        errors += 1

def main():
    ascii_banner = pyfiglet.figlet_format("Tokens Changer By Deino0069", "small")
    print(f"{Fore.CYAN}{ascii_banner}{Fore.RESET}")
    print(f"{Fore.YELLOW}Threads: {config['threads']}{Fore.RESET}")
    
    # Wait for Enter key press to start
    input(f"{Fore.WHITE}Press Enter To Start{Fore.RESET}")
    os.system('cls' if os.name == 'nt' else 'clear')

    proxies = []
    if os.path.exists('input/proxies.txt'):
        with open('input/proxies.txt', 'r') as f:
            proxies = [line.strip() for line in f.readlines()]

    with open('input/tokens.txt', 'r') as input_file, open('output/changed.txt', 'a') as output_file:
        lines = input_file.readlines()
        with concurrent.futures.ThreadPoolExecutor(max_workers=config['threads']) as executor:
            futures = []
            for i, line in enumerate(lines):
                proxy = proxies[i % len(proxies)] if proxies else None
                futures.append(executor.submit(change_password_for_token, line, output_file, proxy))
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Fore.RED}ERROR{Fore.RESET} | Error occurred: {e}")

if __name__ == '__main__':
    main()
    Console.info(f"{Fore.GREEN}SUCCESS{Fore.RESET} | {Fore.MAGENTA}Successfully Changed {changed} Passwords")
    choice = input(f"{Fore.LIGHTMAGENTA_EX}Press Enter To Exit: " + Fore.RESET)