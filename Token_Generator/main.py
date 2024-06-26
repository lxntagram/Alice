import threading, json, time, requests, tls_client, os, random, base64, websocket,re, ctypes, keyboard, traceback, sys, base64
from base64 import b64encode
#----------------------------------------------------------------------_#
from pystyle       import *
from datetime      import datetime
from os            import listdir, path
from random        import choice
from os.path       import isfile, join
from pypresence    import Presence
from colorama      import *


ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
try:
    with open('config.json', 'r') as file:
        config = json.load(file)
except:
    print("Make sure config.json is in the folder!")
    os.abort()

try:
    #-----------HUMANIZATION--------------#
    pfp       = config['user']['humanization']['pfp']
    bio       = config['user']['humanization']['bio']
    hypesquad = config['user']['humanization']['hypesquad']
    pronouns  = config['user']['humanization']['pronouns']

    #-----------PRINTS-CONFIG--------------#

    token_creation_enabled = config["advanced"]["prints"]["token_creation"]
    errors_enabled = config["advanced"]["prints"]["errors"]
    captcha_enabled = config["advanced"]["prints"]["captcha"]
    humanized_enabled = config["advanced"]["prints"]["humanized"]
    unlocked_enabled = config["advanced"]["prints"]["unlocked"]
    locked_enabled = config["advanced"]["prints"]["locked"]
    onlined_enabled = config["advanced"]["prints"]["onlined"]
    verified_enabled = config["advanced"]["prints"]["verified"]
except:
    pfp       = False
    bio       = False
    hypesquad = False
    pronouns  = False

#region Logger
class Log:
    lock = threading.Lock()

    def success(text):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if token_creation_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.green_to_cyan, "SUCCESS", 1) + Colors.gray + " > " + Colors.light_gray + text + Colors.reset)

    def error(text):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if errors_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.red_to_purple, "ERROR", 1) + Colors.gray + " > " + Colors.light_gray + text + Colors.reset)

    def captcha(cap_token, time_n):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if captcha_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.blue_to_cyan, "CAPTCHA", 1) + Colors.gray + " > " + Colors.light_gray + f"[{Colors.light_gray}{cap_token[:16]}...{Colors.gray}] [{Colors.light_gray}{str(time_n)}{Colors.gray}]" + Colors.reset)

    def humanized(data):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if humanized_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.purple_to_blue, "HUMANIZED", 1) + Colors.gray + " > (" + Colors.light_gray + data + Colors.gray + ")" + Colors.reset)

    def unlocked(token):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if unlocked_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.green_to_cyan, "UNLOCKED", 1) + Colors.gray + " > " + Colors.light_gray + token[:30] + "..." + Colors.reset)

    def locked(token):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if locked_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.red_to_purple, "LOCKED", 1) + Colors.gray + " > " + Colors.light_gray + token[:30] + "..." + Colors.reset)

    def onlined(token):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if onlined_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.blue_to_white, "ONLINED", 1) + Colors.gray + " > " + Colors.light_gray + token[:30] + "..." + Colors.reset)

    def verified(token, email):
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        if verified_enabled:
            with Log.lock:
                print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.yellow_to_red, "VERIFIED", 1) + Colors.gray + " > " + Colors.light_gray + f"[{Colors.light_gray}{token[:30]}...{Colors.gray}] [{Colors.light_gray}{email}{Colors.gray}]" + Colors.reset)
total = 0
unlocked = 0
locked = 0

genStartTime = time.time()

class Title:
    def __init__(self):
        self.lock = threading.Lock()
        self.update_title()

    def update_title(self):
            try:
                global unlocked, locked, total
                if (unlocked + locked == 0):
                    unlock_rate = 0
                else:
                    unlock_rate = round((unlocked / (unlocked + locked)) * 100)


                title = f'.gg/g3n | Total: {total} | Unlocked: {unlocked} | Locked: {locked} | Unlock Rate: {unlock_rate}% | Time Elapsed: {round(time.time() - genStartTime, 2)}s'
                ctypes.windll.kernel32.SetConsoleTitleW(title)
            except Exception as e:
                pass

            threading.Timer(0.1, self.update_title).start()

class Status:
    def status():
        try:
            client_id = "1137057084219863202"
            RPC = Presence(client_id)
            RPC.connect()

            last_clear_time = time.time()

            while True:
                if unlocked + locked == 0:
                    unlock_rate = 0
                else:
                    unlock_rate = round((unlocked / (unlocked + locked)) * 100)

                RPC.update(
                    large_image="ast_x9__1_-removebg-preview_1_",
                    large_text="Alice Generator v2",
                    details=f"Unlocked: {unlocked} | Locked: {locked}",
                    state=f"Unlock Rate: {unlock_rate}%",
                    start=int(genStartTime),
                    buttons=[{"label": "Buy Now!", "url": "https://discord.gg/g3n"}]
                )

                current_time = time.time()

                if current_time - last_clear_time >= 200:
                    os.system('cls')
                    last_clear_time = current_time

                time.sleep(1)

        except Exception as e:
            print(e)


#endregion
#region CAPTCHA_APIS
def solver(site_key):
    print("solvin")
    start_time = time.time()
    r = requests.get(url=f"http://ins1.api.401.lol:3001/getCaptcha?sitekey={site_key}&url=discord.com").json()
    print(r)
    res = r['value']
    if(res == "failed"):
        return {"stat":False}
    elif 'P1_' in res:
        Log.captcha(res, round((time.time() - start_time), 2))
        return res





#endregion
#region User
class user:
    def onliner(token):
        pld = {
            "op": 2,
            "d": {
                "token": token,
                "capabilities": 61,
                "properties": {
                    "os": "Windows",
                    "browser": "Safari",
                    "browser_user_agent": ua,
                    "browser_version": "110.0.0.0",
                    "os_version": "10"
                },
                "presence": {
                    "status": random.choice(["online", "idle", "dnd"]),
                    "since": 0,
                    "activities": [{
                        "name": "Custom Status",
                        "type": 4,
                        "state": "Money is key!",
                        "emoji": ""
                    }],
                    "afk": False
                },
                "compress": False,
                "client_state": {
                    "highest_last_message_id": "0"
                }
            }
        }
        conn = websocket.create_connection("wss://gateway.discord.gg/?encoding=json&v=9")
        conn.send(json.dumps(pld))
        Log.onlined(token)

    def getAvatar():
        picture = [f for f in listdir("user/pfps/") if isfile(join("user/pfps/", f))]
        random_picture = choice(picture)
        with open(f'user/pfps/{random_picture}', "rb") as image_file:
            encoded_string = b64encode(image_file.read())
        return encoded_string.decode('utf-8')

    def get_username():
        with open('user/usernames.txt', encoding='utf-8') as file:
            usernames = file.read().splitlines()
        return random.choice(usernames)

    def get_pronouns():
        pronouns = ["he/him", "she/her","they/them", "Switched/On" , "Ask me","it/its","Cool/Hot", "Ama/zing", "the/best"]
        return random.choice(pronouns)

    def get_id():

        print("todo")

    def get_bio():
        biolist = open('./user/bio.txt', encoding='utf-8').read().splitlines()
        bio = random.choice(biolist)
        return bio

    def generate_unique_username(session, proxy):
        headers = {
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
            "User-Agent": ua,
            "X-Track": Misc.xtrack()
        }
        def generate_username(length):
            r = requests.get(url="https://randomuser.me/api/")

            username = r.json()["results"][0]["login"]["username"]
            return username


        valid_username = None
        while valid_username == None:
            user = generate_username(random.randint(5, 16))
            payload = {
                "username": user
            }

            req = session.post("https://discord.com/api/v9/unique-username/username-attempt-unauthed", headers=headers, json=payload, proxy=f"http://{proxy}")
            if not req.json()['taken']:
                valid_username = user
                return valid_username
            else:
                time.sleep(1)

    def generate_random_birthdate():
            year = random.randint(1970, 1999)
            month = random.randint(1, 12)
            if month in [1, 3, 5, 7, 8, 10, 12]:
                day = random.randint(1, 31)
            elif month == 2:
                if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                    day = random.randint(1, 29)
                else:
                    day = random.randint(1, 28)
            else:
                day = random.randint(1, 30)
            birthdate = datetime(year, month, day)
            birthdate_str = birthdate.strftime('%Y-%m-%d')
            return birthdate_str

#endregion
#region Misc
class Misc:
    def proxy():
        with open('data/proxy.txt', encoding='utf-8') as file:
            proxies = file.read().splitlines()
        proxy = random.choice(proxies)
        if '@' in proxy:
            return proxy
        elif len(proxy.split(':')) == 2:
            return proxy
        else:
            if '.' in proxy.split(':')[0]:
                return ':'.join(proxy.split(':')[2:]) + '@' + ':'.join(proxy.split(':')[:2])
            else:
                return ':'.join(proxy.split(':')[:2]) + '@' + ':'.join(proxy.split(':')[2:])

    def xtrack():
        return base64.b64encode(json.dumps({"os":"Windows","browser":"Safari","device":"","system_locale":"en-US","browser_user_agent":ua,"browser_version":"110.0.5481.192","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":5645383,"client_event_source":None}).encode()).decode()
#endregion
#region Cookies
class Cookie:
    def __init__(self, proxy, session):
        self.proxy = proxy
        self.session = session
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
            "User-Agent": ua,
            "X-Track": Misc.xtrack()
        }
    def get_cookies(self):
        while True:
            try:
                response = self.session.get("https://discord.com", headers=self.headers, proxy=f"http://{self.proxy}")
                __cfruid = response.cookies.get('__cfruid')
                __dcfduid = response.cookies.get('__dcfduid')
                __sdcfduid  = response.cookies.get('__sdcfduid')
                fingerprint = self.session.get("https://discord.com/api/v9/experiments", headers=self.headers, proxy=f"http://{self.proxy}").json().get('fingerprint')
                return (__dcfduid, __sdcfduid, __cfruid, fingerprint)
            except Exception as e:
                continue
#endregion

def SolveCaptchaCapmonster(sitekey, url, ua, proxy):
        username_password, ip_port = proxy.split("@")
        username, password = username_password.split(":")
        ip, port = ip_port.split(":")
        solvedCaptcha = None
        taskId = requests.post(
            f"https://api.capmonster.cloud/createTask",
            json={
                "clientKey": config['captcha']['api_key'],
                "task": {
                    "type": "HCaptchaTask",
                    "websiteURL": url,
                    "websiteKey": sitekey,
                    "userAgent": ua,
                    "proxyType": "http",
                    "proxyAddress": ip,
                    "proxyPort": port,
                    "proxyLogin": username,
                    "proxyPassword": password

                },
            },
            timeout=30,
        ).json()

        if taskId.get("errorId") > 0:
            Log.error("Error creating captcha task")
            return None

        taskId = taskId.get("taskId")
        start_time = time.time()
        while not solvedCaptcha:
            captchaData = requests.post(
                f"https://api.capmonster.cloud/getTaskResult",
                json={"clientKey": "66e48c4449ab7b57e861a15e3f6b8be8", "taskId": taskId},
                timeout=30,
            ).json()
            if captchaData["errorId"] > 0:
                Log.error("Error solving captcha")
                return None

            if captchaData.get("status") == "ready":
                solvedCaptcha = captchaData.get("solution").get("gRecaptchaResponse")
                Log.captcha(solvedCaptcha[:16], round(time.time() - start_time, 2))
                return solvedCaptcha

def SolveCaptchaCapsolver(sitekey, url, ua, proxy):
        try:
            while True:
                try:
                    taskId = requests.post("https://api.capsolver.com/createTask", json={
                        "clientKey": config['captcha']['api_key'],
                        "task": {
                            "type": "HCaptchaTurboTask",
                            "websiteURL": url,
                            "websiteKey": sitekey,
                            "proxy": f"http://{proxy}",
                            "enableIPV6": False,
                            "ua": ua
                        }}).json()
                    if taskId['errorId'] != 0:
                        continue
                    else:
                        break
                except:
                    Log.error("Error creating captcha task")
                    continue

            start_time = time.time()
            while True:
                try:
                    result = requests.post("https://api.capsolver.com/getTaskResult", json={
                        "clientKey": "CAP-A5650722CE866186EF90736380C73F40",
                        "taskId": taskId["taskId"]
                    }).json()

                    if result["status"] == "processing":
                        time.sleep(1.5)
                        continue

                    elif result["status"] == "ready":
                        answer = result["solution"]["gRecaptchaResponse"]
                        Log.captcha(answer[:16], round(time.time() - start_time, 2))
                        return answer

                    elif result["status"] == "failed":
                        Log.error(f"Error solving captcha {result}")
                        return None

                    else:
                        return None
                except Exception as e:
                    time.sleep(10)
                    Log.error(f"Error getting captcha result {str(e)}")
                    continue

        except requests.HTTPError as http_err:
            Log.error(f"HTTP error occurred:{http_err}")


        except Exception:
            Log.error(f"An error occurred")
            return None
#region Generator
class Generator:
    def unclaimed():
        global total, unlocked, locked
        proxy = Misc.proxy()
        xtrack = Misc.xtrack()
        session = tls_client.Session(client_identifier="safari_ios_16_0", random_tls_extension_order=True)
        username = user.get_username()
        c = Cookie(proxy, session)
        cookies = c.get_cookies()
        if(config['captcha']['service'] == "capmonster"):
            captcha_token = SolveCaptchaCapmonster("4c672d35-0701-42b2-88c3-78380b0db560", "https://discord.com/", ua, proxy)
        elif config['captcha']['service'] == 'capsolver':
            captcha_token = SolveCaptchaCapsolver("4c672d35-0701-42b2-88c3-78380b0db560", "https://discord.com/", ua, proxy)
        try:
            headers = {
                "authority": "discord.com",
                "method": "POST",
                "path": "/api/v9/auth/register",
                "scheme": "https",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Content-Type": "application/json",
                "Cookie": f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; locale=en-US;',
                "Origin": "https://discord.com",
                "Referer": "https://discord.com/register",
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": "'macOS'",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": ua,
                "X-Debug-Options": "bugReporterEnabled",
                "X-Discord-Locale": "en-US",
                "X-Discord-Timezone": "Europe/Warsaw",
                "X-Fingerprint": cookies[3],
                'x-super-properties': xtrack
            }
            payload = {
                "consent": True,
                "fingerprint": cookies[3],
                "username": username,
                "captcha_key": captcha_token
            }

            req = session.post("https://discord.com/api/v9/auth/register", headers=headers, json=payload, proxy=f"http://{proxy}")
        except Exception as e:
            traceback.print_exc()
            Log.error("Excepted - "+str(e))
        if req.status_code == 201:
            global total
            token = req.json()['token']
            total += 1
            print(total)
            Log.success(f"{token[:30]}...")
            time.sleep(7)
            checker = session.get("https://discord.com/api/v9/users/@me/affinities/users", headers={'authority': 'discord.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; ', 'authorization': token, 'origin': 'https://discord.com', 'referer': 'https://discord.com/@me', 'Content-Type': 'application/json', 'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': ua, 'x-debug-options': 'bugReporterEnabled', 'x-discord-locale': 'en-US', 'x-fingerprint': cookies[3], 'x-super-properties': xtrack}, proxy=f"http://{proxy}")
            if checker.status_code == 200:
                    Log.unlocked(token)
                    global unlocked
                    unlocked += 1
                    print(unlocked)
                    with open("./output/unlocked.txt", "a") as f:
                        f.write(f"{token}\n")
                    time.sleep(3)
                    hmnzd=[]
                    human_headers = {
                                    'authority': 'discord.com',
                                    'method': 'PATCH',
                                    'path': '/api/v9/users/@me/profile',
                                    'scheme': 'https',
                                    'accept': '*/*',
                                    'accept-encoding': 'gzip, deflate, br',
                                    'accept-language': 'en-US',
                                    'authorization': token,
                                    'content-type': 'application/json',
                                    'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]};   locale=en-US;',
                                    'origin': 'https://discord.com',
                                    'referer': 'https://discord.com/channels/@me',
                                    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-ch-ua-platform': '"Windows"',
                                    'sec-fetch-dest': 'empty',
                                    'sec-fetch-mode': 'cors',
                                    'sec-fetch-site': 'same-origin',
                                    'user-agent': ua,
                                    'x-debug-options': 'bugReporterEnabled',
                                    'x-discord-locale': 'en-US',
                                    'x-discord-timezone': 'America/Halifax',
                                    'x-super-properties': xtrack
                                }
                    if pfp:
                        user.onliner(token)
                        time.sleep(5)
                        payload = {
                            "avatar": f"data:image/png;base64,{user.getAvatar()}"
                        }
                        r = session.patch(f"https://discord.com/api/v9/users/@me", json=payload, headers=human_headers, proxy=f"http://{proxy}")
                        if r.status_code == 200:
                            hmnzd.append("PFP")

                    if bio:
                        time.sleep(3)
                        payload = {"bio": str(user.get_bio())}
                        r = session.patch('https://discord.com/api/v9/users/@me/profile', headers=human_headers, json=payload, proxy=f"http://{proxy}")

                        if r.status_code == 200:
                            hmnzd.append("BIO")

                    if pronouns:
                        time.sleep(2)
                        payload ={"pronouns":str(user.get_pronouns())}
                        r = session.patch('https://discord.com/api/v9/users/@me/profile', headers=human_headers, json=payload, proxy=f"http://{proxy}")

                        if r.status_code == 200:
                            hmnzd.append("PRONOUNS")


                    if hypesquad:
                        time.sleep(4)
                        payload = {"house_id": random.choice([1,2,3])}
                        r = session.post('https://discord.com/api/v9/hypesquad/online', headers=human_headers, json=payload, proxy=f"http://{proxy}")
                        if r.status_code == 204:
                            hmnzd.append("HYPESQUAD")

                    if pfp or bio or hypesquad or pronouns:
                        humanized_info_str = (", ".join(hmnzd) + ",")[:-1]
                        Log.humanized(humanized_info_str)
            else:
                global locked
                locked += 1
                print(locked)
                Log.locked(token)
                with open("./output/locked.txt", "a") as f:
                    f.write(f"{token}\n")
    def ev():
        password =config['user']['password']# TEMP


        try:
            kopechka_request = requests.get(url=f"https://api.kopeechka.store/mailbox-get-email?site=discord.com&mail_type={config['email_verification']['mail_type']}&sender=&regex=&token={config['email_verification']['kopechka_key']}&soft=&investor=&type=JSON&subject=&clear=&api=2.0")
            if kopechka_request.json():
                email = kopechka_request.json()['mail']
                email_id = kopechka_request.json()['id']
            else:
                raise Exception
        except:
            Log.error("Error getting mail")
            return
        proxy = Misc.proxy()
        captcha_token = ""
        while True:
            try:

                if(config['captcha']['service'] == "capmonster"):
                    captcha_token = SolveCaptchaCapmonster("4c672d35-0701-42b2-88c3-78380b0db560", "https://discord.com/", ua, proxy)
                elif config['captcha']['service'] == 'capsolver':
                    captcha_token = SolveCaptchaCapsolver("4c672d35-0701-42b2-88c3-78380b0db560", "https://discord.com/", ua, proxy)
                if captcha_token != None:
                    break
            except:
                 continue
        try:
            #captcha_token = solver("4c672d35-0701-42b2-88c3-78380b0db560")
            xtrack = Misc.xtrack()
            session = tls_client.Session(client_identifier=random.choice(["safari_ios_16_0", "chrome112", "safari_ios_15_6", "okhttp4_android_13", "safari_16_0", "opera_90","opera_90"]), random_tls_extension_order=True)


            username = user.get_username()
            c = Cookie(proxy, session)
            cookies = c.get_cookies()

            headers = {
                "authority": "discord.com",
                "method": "POST",
                "path": "/api/v9/auth/register",
                "scheme": "https",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Content-Type": "application/json",
                "Cookie": f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; locale=en-US;',
                "Origin": "https://discord.com",
                "Referer": "https://discord.com/register",
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": "'macOS'",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": ua,
                "X-Debug-Options": "bugReporterEnabled",
                "X-Discord-Locale": "en-US",
                "X-Discord-Timezone": "Europe/Warsaw",
                'x-captcha-Key': captcha_token,
                "X-Fingerprint": cookies[3],
                'x-super-properties': xtrack
            }

            payload = {
                            "fingerprint": cookies[3],
                            "email": email,
                            "username": user.generate_unique_username(session, proxy),
                            "global_name": user.get_username(),
                            "password": password,
                            "consent": True,
                            "date_of_birth": f"{user.generate_random_birthdate()}",
                            "promotional_email_opt_in": False,
                            "unique_username_registration": True
                        }

            r = session.post("https://discord.com/api/v9/auth/register", headers=headers, json=payload, proxy=f"http://{proxy}")
            
        except Exception as e:
            Log.error("Error caught! Show this to developer: "+ base64.b64encode(f'{"Part":"Reqto","Line": {traceback.extract_tb(sys.exc_info()[2])[-1][1]}, "err":{str(e)}}'.encode('utf-8')).decode('utf-8'))
        if r.status_code == 201:

            token = r.json()['token']
            user.onliner(token)
            try:
                with open("./output/total.txt", "a") as f:
                    f.write(f"{token}\n")
            except:
                None
            global total
            total += 1
            Log.success(f"{token[:30]}...")
            link = None
            while link == None:
                    email_verify = requests.get(url=f"https://api.kopeechka.store/mailbox-get-message?full=1&id={email_id}&token={config['email_verification']['kopechka_key']}&type=json&api=2.0")
                    if email_verify.json()['value'] != "WAIT_LINK":
                        link = email_verify.json()['value']
                        break
                    time.sleep(2)

            response = requests.head(email_verify.json()['value'], allow_redirects=True)
            final_url = response.url
            token_match = re.search(r"#token=([^&]*)", final_url)
            verify_token = token_match.group(1)
            verified = False
            try:
                headerse = {
                                        "Accept": "*/*",
                                        "Accept-Encoding": "gzip, deflate, br",
                                        "Accept-Language": "en-US,en;q=0.5",
                                        "Content-Type": "application/json",
                                        "Origin": "https://discord.com",
                                        "Referer": "https://discord.com/verify",
                                        "Sec-Fetch-Dest": "empty",
                                        "Sec-Fetch-Mode": "cors",
                                        "Sec-Fetch-Site": "same-origin",
                                        "User-Agent": ua,
                                        'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; ',
                                        "X-Debug-Options": "bugReporterEnabled",
                                        "X-Discord-Locale": "en-US",
                                        "X-Discord-Timezone": "Europe/Warsaw",
                                        "X-Super-Properties": xtrack,
                                        "Authorization": token,
                                }

                payloade = {
                                        "token": verify_token,
                                }
                verify_r = session.post("https://discord.com/api/v9/auth/verify", headers=headerse, json=payloade, proxy=f"http://{proxy}")
                if verify_r.status_code != 200:
                    raise Exception
                verified = True
            except:
                verify_topken = ""
                if config['email_verification']['captcha']['solve_captcha'] == True:
                    while True:
                        try:
                            if(config['captcha']['service'] == "capmonster"):
                                verify_topken = SolveCaptchaCapmonster("f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "https://discord.com/", ua, proxy)
                            elif config['captcha']['service'] == 'capsolver':
                                verify_topken = SolveCaptchaCapsolver("f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "https://discord.com/", ua, proxy)
                            if verify_topken != None:
                                break
                        except:
                            continue
                    headerse = {
                                            "Accept": "*/*",
                                            "Accept-Encoding": "gzip, deflate, br",
                                            "Accept-Language": "en-US,en;q=0.5",
                                            "Content-Type": "application/json",
                                            "Origin": "https://discord.com",
                                            "Referer": "https://discord.com/verify",
                                            "Sec-Fetch-Dest": "empty",
                                            "Sec-Fetch-Mode": "cors",
                                            "Sec-Fetch-Site": "same-origin",
                                            "User-Agent": ua,
                                            'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; ',
                                            "X-Debug-Options": "bugReporterEnabled",
                                            "X-Discord-Locale": "en-US",
                                            "X-Discord-Timezone": "Europe/Warsaw",
                                            "X-Super-Properties": xtrack,
                                            "Authorization": token,
                                            "X-Captcha-Key": verify_topken,
                                    }

                    payloade = {
                                            "token": verify_token,
                                    }
                    verify_r = session.post("https://discord.com/api/v9/auth/verify", headers=headerse, json=payloade, proxy=f"http://{proxy}")
                    verified = True
            if verified == True:
                Log.verified(token, email)
            while True:
                try:
                    checker = session.get("https://discord.com/api/v9/users/@me/affinities/users", headers={'authority': 'discord.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]}; ', 'authorization': token, 'origin': 'https://discord.com', 'referer': 'https://discord.com/@me', 'Content-Type': 'application/json', 'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': ua, 'x-debug-options': 'bugReporterEnabled', 'x-discord-locale': 'en-US', 'x-fingerprint': cookies[3], 'x-super-properties': xtrack}, proxy=f"http://{proxy}")
                    break
                except:
                    continue
            if checker.status_code == 200:
                Log.unlocked(token)
                global unlocked
                unlocked += 1
                with open("./output/unlocked.txt", "a") as f:
                    f.write(f"{email}:{password}:{token}\n")
                    time.sleep(3)
                    hmnzd=[]
                    human_headers = {
                                    'authority': 'discord.com',
                                    'method': 'PATCH',
                                    'path': '/api/v9/users/@me/profile',
                                    'scheme': 'https',
                                    'accept': '*/*',
                                    'accept-encoding': 'gzip, deflate, br',
                                    'accept-language': 'en-US',
                                    'authorization': token,
                                    'content-type': 'application/json',
                                    'cookie': f'__dcfduid={cookies[0]}; __sdcfduid={cookies[1]}; __cfruid={cookies[2]};   locale=en-US;',
                                    'origin': 'https://discord.com',
                                    'referer': 'https://discord.com/channels/@me',
                                    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-ch-ua-platform': '"Windows"',
                                    'sec-fetch-dest': 'empty',
                                    'sec-fetch-mode': 'cors',
                                    'sec-fetch-site': 'same-origin',
                                    'user-agent': ua,
                                    'x-debug-options': 'bugReporterEnabled',
                                    'x-discord-locale': 'en-US',
                                    'x-discord-timezone': 'America/Halifax',
                                    'x-super-properties': xtrack
                                }
                    if pfp:
                        user.onliner(token)
                        time.sleep(5)
                        payload = {
                            "avatar": f"data:image/png;base64,{user.getAvatar()}"
                        }
                        r = session.patch(f"https://discord.com/api/v9/users/@me", json=payload, headers=human_headers, proxy=f"http://{proxy}")
                        if r.status_code == 200:
                            hmnzd.append("PFP")

                    if bio:
                        time.sleep(3)
                        payload = {"bio": str(user.get_bio())}
                        r = session.patch('https://discord.com/api/v9/users/@me/profile', headers=human_headers, json=payload, proxy=f"http://{proxy}")

                        if r.status_code == 200:
                            hmnzd.append("BIO")

                    if pronouns:
                        time.sleep(2)
                        payload ={"pronouns":str(user.get_pronouns())}
                        r = session.patch('https://discord.com/api/v9/users/@me/profile', headers=human_headers, json=payload, proxy=f"http://{proxy}")

                        if r.status_code == 200:
                            hmnzd.append("PRONOUNS")


                    if hypesquad:
                        time.sleep(4)
                        payload = {"house_id": random.choice([1,2,3])}
                        r = session.post('https://discord.com/api/v9/hypesquad/online', headers=human_headers, json=payload, proxy=f"http://{proxy}")
                        if r.status_code == 204:
                            hmnzd.append("HYPESQUAD")

                    if pfp or bio or hypesquad or pronouns:
                        humanized_info_str = (", ".join(hmnzd) + ",")[:-1]
                        Log.humanized(humanized_info_str)
            else:
                global locked
                locked += 1
                Log.locked(token)
                with open("./output/locked.txt", "a") as f:
                    f.write(f"{token}\n")



        else:
            Log.error(f'Failed creating token {r.status_code} {r.text}')
            return
    def full():
        print("#TODO")
#endregion



def choose_verification_option(options):
    selected_index = 0
    cooldown_time = 0.2
    option_selected = False

    def display_options():
        os.system("cls" if os.name == "nt" else "clear")
        for i, option in enumerate(options):
            if i == selected_index:
                print(f"{Fore.LIGHTBLUE_EX}> {Fore.RESET}{option}")
            else:
                print(option)

    display_options()
    last_key_press_time = 0

    while True:
        if keyboard.is_pressed('down') and time.time() - last_key_press_time >= cooldown_time:
            selected_index = (selected_index + 1) % len(options)
            display_options()
            last_key_press_time = time.time()
            option_selected = False

        if keyboard.is_pressed('up') and time.time() - last_key_press_time >= cooldown_time:
            selected_index = (selected_index - 1) % len(options)
            display_options()
            last_key_press_time = time.time()
            option_selected = False

        if keyboard.is_pressed('enter') and not option_selected:
            return options[selected_index]

        if keyboard.is_pressed('q'):
            break

        time.sleep(0.05)

def generate_loop_unc():
    while True:
        try:
            Generator.unclaimed()
        except Exception as e:
            print(e)
            continue

def generate_loop_ev():
    while True:
        try:
            Generator.ev()
        except Exception as e:
            print(e)
            continue

def generate_loop_fv():
    while True:
        try:
            Generator.full()
        except Exception as e:
            print(e)
            continue

def main():
    os.system('cls')
    threads = int(input(f"{Colors.reset}({Colors.light_blue}?{Colors.reset}) Threads >> "))
    os.system('cls')
    time.sleep(0.2)
    typeg = choose_verification_option(['Unclaimed (no email, no phone)', 'Email Verified (verified email)', 'Full Verified (verified email & phone)'])
    os.system('cls')
    if typeg == 'Unclaimed (no email, no phone)':
        threading.Thread(target=Status.status).start()
        for number in range(threads):
            threading.Thread(target=generate_loop_unc).start()
        title =  Title()
        title.update_title()
    elif typeg == 'Email Verified (verified email)':
        threading.Thread(target=Status.status).start()
        for number in range(threads):
            threading.Thread(target=generate_loop_ev).start()
        title =  Title()
        title.update_title()
    elif typeg == 'Full Verified (verified email & phone)':
        threading.Thread(target=Status.status).start()
        for number in range(threads):
            threading.Thread(target=generate_loop_fv).start()
        title =  Title()
        title.update_title()

main()
