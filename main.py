import asyncio
import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Tuple
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import codecs
import time
import base64
import re
import urllib3
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters
)
import tempfile
import warnings
from concurrent.futures import ThreadPoolExecutor, Future, as_completed

# Fix warning filter
warnings.filterwarnings(
    "ignore",
    message="If 'per_message=False'",
    category=UserWarning,
    module='telegram.ext._conversationhandler'
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SELECTING_REGION, ENTERING_COUNT = range(2)

BOT_TOKEN = "8542384756:AAG5PPM0BXYXXVqDPfbgfd1b4ztQSKB7TBY"

FIXED_NAME = "HawkXMHM"
FIXED_PASSWORD_PREFIX = "67353272Moe"

REGION_LANG = {
    "TH": "th", "IND": "hi", "BR": "pt"
}

hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
hex_data = "8J+agCBCbGFjayBBcGlzIEFjY291bnQgR2VuZXJhdG9yIPCfkqsgQnkgQkxBQ0tfQVBJcyB8IE5vdCBGb3IgU2FsZSDwn5Kr"
client_data = base64.b64decode(hex_data).decode('utf-8')
GARENA = "TUgN"

ACCOUNT_RARITY_PATTERNS = {
    "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
    "REPEATED_DIGITS_3": [r"(\d)\1\1(\d)\2\2", 2],
    "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
    "SEQUENTIAL_4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
    "PALINDROME_4": [r"^(\d)(\d)\2\1$", 3],
    "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
    "SPECIAL_COMBINATIONS_MED": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MIRROR_PATTERN_HIGH": [r"^(\d{2,3})\1$", 3],
    "MIRROR_PATTERN_MED": [r"(\d{2})0\1", 2],
    "GOLDEN_RATIO": [r"1618|0618", 3]
}

user_sessions: Dict[int, Dict] = {}
generation_tasks: Dict[str, Dict] = {}

class FreeFireRareAccountGenerator:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_counter = 0
        self.rare_counter = 0
        self.running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=800)
        
    def stop_generation(self):
        """Stop the generation process"""
        self.running = False
        
    def check_account_rarity(self, account_data):
        account_id = account_data.get("account_id", "")
        if account_id == "N/A" or not account_id:
            return 0
        
        rarity_score = 0
        detected_patterns = []
        
        for rarity_type, pattern_data in ACCOUNT_RARITY_PATTERNS.items():
            pattern = pattern_data[0]
            score = pattern_data[1]
            if re.search(pattern, account_id):
                rarity_score += score
                detected_patterns.append(rarity_type)
        
        account_id_digits = [int(d) for d in account_id if d.isdigit()]
        
        if len(set(account_id_digits)) == 1 and len(account_id_digits) >= 4:
            rarity_score += 5
            detected_patterns.append("UNIFORM_DIGITS")
        
        if len(account_id_digits) >= 4:
            differences = [account_id_digits[i+1] - account_id_digits[i] for i in range(len(account_id_digits)-1)]
            if len(set(differences)) == 1:
                rarity_score += 4
                detected_patterns.append("ARITHMETIC_SEQUENCE")
        
        if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
            rarity_score += 3
            detected_patterns.append("LOW_ACCOUNT_ID")
        
        return rarity_score

    def generate_random_name(self, base_name):
        exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
        number = random.randint(1, 99999)
        number_str = f"{number:05d}"
        exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
        return f"{base_name[:7]}{exponent_str}"
    
    def generate_custom_password(self, prefix):
        garena_decoded = base64.b64decode(GARENA).decode('utf-8')
        characters = string.ascii_uppercase + string.digits
        random_part1 = ''.join(random.choice(characters) for _ in range(5))
        random_part2 = ''.join(random.choice(characters) for _ in range(5))
        return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"
    
    def EnC_Vr(self, N):
        if N < 0: 
            return b''
        H = []
        while True:
            BesTo = N & 0x7F 
            N >>= 7
            if N: 
                BesTo |= 0x80
            H.append(BesTo)
            if not N: 
                break
        return bytes(H)
    
    def CrEaTe_VarianT(self, field_number, value):
        field_header = (field_number << 3) | 0
        return self.EnC_Vr(field_header) + self.EnC_Vr(value)
    
    def CrEaTe_LenGTh(self, field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return self.EnC_Vr(field_header) + self.EnC_Vr(len(encoded_value)) + encoded_value
    
    def CrEaTe_ProTo(self, fields):
        packet = bytearray()    
        for field, value in fields.items():
            if isinstance(value, dict):
                nested_packet = self.CrEaTe_ProTo(value)
                packet.extend(self.CrEaTe_LenGTh(field, nested_packet))
            elif isinstance(value, int):
                packet.extend(self.CrEaTe_VarianT(field, value))           
            elif isinstance(value, str) or isinstance(value, bytes):
                packet.extend(self.CrEaTe_LenGTh(field, value))           
        return packet
    
    def E_AEs(self, Pc):
        Z = bytes.fromhex(Pc)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(Z, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted

    def encrypt_api(self, plain_text):
        plain_text = bytes.fromhex(plain_text)
        aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(plain_text, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted.hex()
    
    def create_acc(self, region, account_name, password_prefix, is_ghost=False):
        try:
            password = self.generate_custom_password(password_prefix)
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            url = "https://100067.connect.garena.com/oauth/guest/register"
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'uid' in response.json():
                uid = response.json()['uid']
                return self.token(uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            return None
    
    def token(self, uid, password, region, account_name, password_prefix, is_ghost=False):
        try:
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            }
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": key,
                "client_id": "100067"
            }
            
            response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'open_id' in response.json():
                open_id = response.json()['open_id']
                access_token = response.json()["access_token"]
                refresh_token = response.json()['refresh_token']
                
                result = self.encode_string(open_id)
                field = self.to_unicode_escaped(result['field_14'])
                field = codecs.decode(field, 'unicode_escape').encode('latin1')
                return self.Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            return None
    
    def encode_string(self, original):
        keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                     0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
        encoded = ""
        for i in range(len(original)):
            orig_byte = ord(original[i])
            key_byte = keystream[i % len(keystream)]
            result_byte = orig_byte ^ key_byte
            encoded += chr(result_byte)
        return {"open_id": original, "field_14": encoded}
    
    def to_unicode_escaped(self, s):
        return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)
    
    def Major_Regsiter(self, access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
        try:
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            else:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            
            name = self.generate_random_name(account_name)
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",   
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }

            lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            payload = {
                1: name,
                2: access_token,
                3: open_id,
                5: 102000007,
                6: 4,
                7: 1,
                13: 1,
                14: field,
                15: lang_code,
                16: 1,
                17: 1
            }

            payload_bytes = self.CrEaTe_ProTo(payload)
            encrypted_payload = self.E_AEs(payload_bytes.hex())
            
            response = requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
            
            if response.status_code == 200:
                login_result = self.perform_major_login(uid, password, access_token, open_id, region, is_ghost)
                account_id = login_result.get("account_id", "N/A")
                jwt_token = login_result.get("jwt_token", "")
                
                account_data = {
                    "uid": uid, 
                    "password": password, 
                    "name": name, 
                    "region": "GHOST" if is_ghost else region, 
                    "status": "success",
                    "account_id": account_id,
                    "jwt_token": jwt_token
                }
                
                return account_data
            else:
                return None
        except Exception as e:
            return None
    
    def perform_major_login(self, uid, password, access_token, open_id, region, is_ghost=False):
        try:
            lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            
            payload_parts = [
                b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
                lang.encode("ascii"),
                b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            ]
            
            payload = b''.join(payload_parts)
            
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorLogin"
            else:
                url = "https://loginbp.common.ggbluefox.com/MajorLogin"
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1"
            }

            data = payload
            data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            d = self.encrypt_api(data.hex())
            final_payload = bytes.fromhex(d)

            response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
            
            if response.status_code == 200 and len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = response.text[jwt_start:]
                    second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                    if second_dot != -1:
                        jwt_token = jwt_token[:second_dot + 44]
                        
                        account_id = self.decode_jwt_token(jwt_token)
                        return {"account_id": account_id, "jwt_token": jwt_token}
            
            return {"account_id": "N/A", "jwt_token": ""}
        except Exception as e:
            return {"account_id": "N/A", "jwt_token": ""}
    
    def decode_jwt_token(self, jwt_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                padding = 4 - len(payload_part) % 4
                if padding != 4:
                    payload_part += '=' * padding
                decoded = base64.urlsafe_b64decode(payload_part)
                data = json.loads(decoded)
                account_id = data.get('account_id') or data.get('external_id')
                if account_id:
                    return str(account_id)
        except Exception:
            pass
        return "N/A"
    
    def generate_account_wrapper(self, args):
        """Wrapper function for thread pool execution with retry logic"""
        region, account_name, password_prefix, is_ghost, retry_count = args
        max_retries = 3
        
        for attempt in range(max_retries):
            if not self.running:
                return None
                
            try:
                account_result = self.create_acc(region, account_name, password_prefix, is_ghost)
                if account_result:
                    with self.lock:
                        self.success_counter += 1
                        current_count = self.success_counter

                    rarity_score = self.check_account_rarity(account_result)
                    
                    return {
                        "account": account_result,
                        "rarity_score": rarity_score,
                        "count": current_count,
                        "attempts": attempt + 1
                    }
            except Exception:
                pass
            
            # Small delay between retries
            time.sleep(0.1 * (attempt + 1))
        
        return None

generator = FreeFireRareAccountGenerator()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    
    keyboard = [
        [InlineKeyboardButton("TH (th)", callback_data="region_TH")],
        [InlineKeyboardButton("IND (hi)", callback_data="region_IND")],
        [InlineKeyboardButton("BR (pt)", callback_data="region_BR")],
        [InlineKeyboardButton("👻 GHOST Mode", callback_data="region_GHOST")],
        [InlineKeyboardButton("❌ Cancel", callback_data="cancel")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🎮 Free Fire Account Generator\n\n"
        "Select region:",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )
    
    return SELECTING_REGION

async def region_selected(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    data = query.data
    
    if data == "cancel":
        await query.edit_message_text("❌ Cancelled.")
        return ConversationHandler.END
    
    if data.startswith("region_"):
        region = data.replace("region_", "")
        
        if user_id not in user_sessions:
            user_sessions[user_id] = {}
        user_sessions[user_id]['region'] = region
        
        await query.edit_message_text(
            f"✅ Region: {region}\n"
            f"Enter number of accounts (1-9999):"
        )
        
        return ENTERING_COUNT

async def get_account_count(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text
    
    try:
        count = int(text)
        if 1 <= count <= 9999:
            region = user_sessions[user_id]['region']
            is_ghost = region == "GHOST"
            region_code = "BR" if is_ghost else region
            
            task_id = f"{user_id}_{int(time.time())}"
            generation_tasks[task_id] = {
                'user_id': user_id,
                'chat_id': update.message.chat_id,
                'region': region_code,
                'count': count,
                'name': FIXED_NAME,
                'password': FIXED_PASSWORD_PREFIX,
                'is_ghost': is_ghost,
                'status': 'running',
                'start_time': time.time(),
                'generated': 0,
                'rare_found': 0,
                'failed_attempts': 0,
                'total_attempts': 0,
                'retry_queue': asyncio.Queue(),
                'lock': asyncio.Lock()
            }
            
            await update.message.reply_text(f"🚀 Starting generation of {count} accounts...")
            
            asyncio.create_task(run_generation(task_id, context))
            
        else:
            await update.message.reply_text("❌ Enter 1–9999.")
            return ENTERING_COUNT
    except ValueError:
        await update.message.reply_text("❌ Enter a number.")
        return ENTERING_COUNT

    return ConversationHandler.END

async def run_generation(task_id: str, context: ContextTypes.DEFAULT_TYPE):
    task = generation_tasks.get(task_id)
    if not task:
        return
    
    user_id = task['user_id']
    chat_id = task['chat_id']
    
    region = task['region']
    count = task['count']
    name = task['name']
    password = task['password']
    is_ghost = task['is_ghost']
    
    try:
        generator.running = True
        generator.success_counter = 0
        
        accounts_by_score = {}
        pending_accounts = count
        
        # Submit initial batch of tasks
        futures = []
        for i in range(min(count, 10)):  # Start with 10 concurrent tasks
            args = (region, name, password, is_ghost, 0)
            future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
            futures.append((future, i))
            async with task['lock']:
                task['total_attempts'] += 1
        
        processed_futures = 0
        
        while pending_accounts > 0 and generator.running:
            # Process completed futures
            for future, index in futures[:]:
                if future.done():
                    processed_futures += 1
                    futures.remove((future, index))
                    
                    result = future.result()
                    
                    if result:
                        # Successful generation
                        account_data = result['account']
                        score = result["rarity_score"]
                        
                        async with task['lock']:
                            task['generated'] += 1
                            pending_accounts -= 1
                        
                        # Store account by score
                        if score not in accounts_by_score:
                            accounts_by_score[score] = []
                        accounts_by_score[score].append(account_data)
                        
                        # Send to user with #number tag
                        account_number = task['generated']
                        
                        if score > 1:
                            async with task['lock']:
                                task['rare_found'] += 1
                            await context.bot.send_message(
                                chat_id=chat_id,
                                text=f"#{account_number} ✨ ID: {account_data['account_id']}\n"
                                     f"• Uid: {account_data['uid']}\n"
                                     f"• Name: {account_data['name']}\n"
                                     f"• Password: {account_data['password']}\n"
                                     f"• Score: {score}"
                            )
                        else:
                            await context.bot.send_message(
                                chat_id=chat_id,
                                text=f"#{account_number} {account_data['account_id']}"
                            )
                    else:
                        # Failed generation, add to retry queue
                        async with task['lock']:
                            task['failed_attempts'] += 1
                            # Add new task to replace failed one
                            args = (region, name, password, is_ghost, 0)
                            new_future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
                            futures.append((new_future, len(futures)))
                            task['total_attempts'] += 1
            
            # Submit more tasks if we have capacity
            while len(futures) < 10 and pending_accounts > 0:
                args = (region, name, password, is_ghost, 0)
                future = generator.thread_pool.submit(generator.generate_account_wrapper, args)
                futures.append((future, len(futures)))
                async with task['lock']:
                    task['total_attempts'] += 1
            
            # ❌ Removed progress messages completely
            # No more progress updates sent to user
            
            # Small delay to prevent busy waiting
            await asyncio.sleep(0.1)
        
        # Wait for any remaining futures
        for future, index in futures:
            if not future.done():
                try:
                    future.result(timeout=5)
                except:
                    pass
        
        task['status'] = 'completed'
        generator.stop_generation()
        
        elapsed = time.time() - task['start_time']
        
        summary = (
            f"✅ Generation Complete!\n"
            f"🎯 Requested: {count}\n"
            f"✅ Successfully Generated: {task['generated']}\n"
            f"✨ Rare Accounts (Score > 1): {task['rare_found']}\n"
            f"🔄 Total Attempts: {task['total_attempts']}\n"
            f"⏱️ Time Taken: {elapsed:.2f}s\n"
            f"⚡ Speed: {task['generated']/elapsed:.2f} accounts/sec"
        )
        await context.bot.send_message(chat_id=chat_id, text=summary)
        
        # Save accounts to files
        if task['generated'] > 0:
            mmt = datetime.now().strftime('%Y%m%d_%H%M%S')
            for score, accounts in accounts_by_score.items():
                if accounts:  # Only save if there are accounts
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
                        json.dump(accounts, f, indent=2, ensure_ascii=False)
                        file_path = f.name
                    with open(file_path, 'rb') as f:
                        await context.bot.send_document(
                            chat_id=chat_id,
                            document=f,
                            filename=f"score_{score}_{mmt}.json",
                            caption=f"Score {score} - {len(accounts)} accounts"
                        )
                    os.unlink(file_path)
        
        # Cleanup
        if user_id in user_sessions:
            del user_sessions[user_id]
        if task_id in generation_tasks:
            del generation_tasks[task_id]
            
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"❌ Error: {str(e)}")
    finally:
        generator.stop_generation()

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if user_id in user_sessions:
        del user_sessions[user_id]
    generator.stop_generation()
    await update.message.reply_text("❌ Cancelled.")
    return ConversationHandler.END

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    generator.stop_generation()
    await update.message.reply_text("🛑 Stopped.")

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"📊 Total Generated: {generator.success_counter}")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🎮 Free Fire Account Generator\n\n"
        "Commands:\n"
        "/start - Start account generation\n"
        "/stop - Stop current generation\n"
        "/stats - Show statistics\n"
        "/help - Show this help\n\n"
        "• Fixed name & password\n"
        "• Multi-threaded generation\n"
        "• Rarity scoring system\n"
        "• Automatic retry on failure"
    )

def main() -> None:
    application = Application.builder().token(BOT_TOKEN).build()
    
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            SELECTING_REGION: [CallbackQueryHandler(region_selected)],
            ENTERING_COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_account_count)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        per_message=False,
        per_user=True,
        per_chat=True
    )
    
    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("cancel", cancel))
    
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
