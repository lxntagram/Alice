1#imports
import base64
import tls_client
import json
import random
import requests
import time
import re
import threading
from pystyle import *
from datetime import datetime

ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.192 Safari/537.36"

class Log:
    lock = threading.Lock()

    def success(text):
        current_time = datetime.now().strftime("%H:%M")
        with Log.lock:
            print(f"{Colors.dark_gray}{current_time} {Colors.reset}({Colors.green}${Colors.reset}) Sent invite to {Colorate.Horizontal(Colors.green_to_yellow, text, 1)}{Colors.reset}")

    def error(text):
        current_time = datetime.now().strftime("%H:%M")
        with Log.lock:
            print(f"{Colors.dark_gray}{current_time} {Colors.reset}({Colors.red}!{Colors.reset}) Failed to sent invite to {Colorate.Horizontal(Colors.red_to_yellow, text, 1)}{Colors.reset}")

    def disabled(text):
        current_time = datetime.now().strftime("%H:%M")
        with Log.lock:
            print(f"{Colors.dark_gray}{current_time} {Colors.reset}({Colors.yellow}/{Colors.reset}) {Colorate.Horizontal(Colors.red_to_yellow, text, 1)}{Colors.reset} has disabled friend requests.")

class Misc:
    def xtrack():
            return base64.b64encode(json.dumps({"os":"Windows","browser":"Chrome","device":"","system_locale":"en-US","browser_user_agent": ua ,"browser_version":"110.0.5481.192","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":5645383,"client_event_source":None}).encode()).decode()

    def buildnum():
        res = requests.get("https://discord.com/login").text
        file_with_build_num = 'https://discord.com/assets/' + re.compile(r'assets/+([a-z0-9]+)\.js').findall(res)[-2]+'.js'
        req_file_build = requests.get(file_with_build_num).text
        index_of_build_num = req_file_build.find('buildNumber')+24
        return int(req_file_build[index_of_build_num:index_of_build_num+6])

class Cookie:
    def __init__(self, proxy, session, tok):
        self.user_agent = ua
        self.proxy = proxy
        self.session = session
        self.token = tok
        self.headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US",
            "Alt-Used": "discord.com",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Host": "discord.com",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "TE": "trailers",
            "User-Agent": self.user_agent,
            "X-Track": Misc.xtrack()
        }

    def get_cookies(self):
        try:
            response = self.session.get('https://discord.com', headers=self.headers)
            __cfruid = response.cookies.get('__cfruid')
            __dcfduid = response.cookies.get('__dcfduid')
            __sdcfduid  = response.cookies.get('__sdcfduid')
            apis = ['https://discord.com/api/v9/experiments' , 'https://canary.discord.com/api/v9/experiments' , 'https://ptb.discord.com/api/v9/experiments']
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', headers=self.headers).json().get('fingerprint')
            return (__dcfduid, __sdcfduid, __cfruid, fingerprint)
        except Exception as e:
            print(e) #
    def getCf_clearance(self):
        cookies={}
        response = requests.post('https://discord.com/cdn-cgi/challenge-platform/h/b/jsd/r/808ba948bee59326', cookies=cookies, headers=self.headers)
        for cookie in response.cookies:
            cookies[cookie.name] = cookie.value
        return response.cookies.get('cf_clearance') # works now
class Sender:
    def __init__(self, sessin, tokn, data):
        self.session = sessin
        self.token = tokn
        self.dat = data                # ty
        #cook = Cookie(0, sessin, tokn)
        #self.cfsomething = cook.getCf_clearance()
        self.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.6',
            'authorization': token,
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'cookie': '__dcfduid=c40c6530323b11eea6943d48a33b85d7; __sdcfduid=c40c6531323b11eea6943d48a33b85d74e3b255172df6241336655bdb13cfc6f62c22c46e9f9bfbe6ae02f72ef4c82d7; __cfruid=f49721d5aad5fe037eb8c3e5ef1e9f386333ff8b-1691316566; locale=en-GB',
            'origin': 'https://discord.com',
            'pragma': 'no-cache',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc':'1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-super-properties': base64.b64encode(json.dumps({
            "os":"Windows",
            "browser":"Chrome",
            "device":"",
            "system_locale":"en-US",
            "browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "browser_version":"115.0.0.0",
            "os_version":"10",
            "referrer":"",
            "referring_domain":"",
            "referrer_current":"",
            "referring_domain_current":"",
            "release_channel":"stable",
            "client_build_number": Misc.buildnum(),
            "client_event_source":"null"
        }, separators=(',', ':')).encode()).decode()
}

    def sender(self, username):
        payload = {}
        if '#' in username:
            parts = username.split('#', 1)
            if len(parts) == 2 and parts[1].isdigit():
                payload = {'username': parts[0], 'discriminator': parts[1]}
        else:
            payload = {"username":username, "discriminator": None}
        cook = Cookie(0, self.session, self.token)
        r = self.session.post("https://discord.com/api/v9/users/@me/relationships", headers=self.headers, json=payload) # This won't work, and cookies are in headers already, so it will add them twicem
        if r.status_code == 204:
            Log.success(username)

        else:
            print(r.status_code)
            print(r.text)


identifiers = ['safari_15_3', 'safari_15_6_1', 'safari_16_0']
#session = tls_client.Session(client_identifier=random.choice(identifiers), random_tls_extension_order=True)
tkns=[]
with open('tokens.txt', 'r+') as f:
    tkns = f.read().splitlines()
users=[]
with open('users.txt', 'r+') as f:
    users = f.read().splitlines()
threads = []

def worker(token):
    session = tls_client.Session(client_identifier=random.choice(identifiers), random_tls_extension_order=True)
    cook = Cookie(0, session, token)
    data = cook.get_cookies()
    sender = Sender(session, random.choice(tkns), data)
    sender.sender(user)

def 
for token in tkns:
    thread = threading.Thread(target=worker_function, args=(i,))
    thread.start()
    threads.append(thread)
for thread in threads: # wait for threads end
    thread.join()

print("All threads have finished.")
