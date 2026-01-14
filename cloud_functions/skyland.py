import hashlib
import hmac
import json
import logging
import threading
import time
import re
import os
from urllib import parse
from typing import Optional, Tuple
from datetime import date
from configparser import ConfigParser, NoSectionError, NoOptionError
import requests

header = {
    'cred': 'cred',
    'User-Agent': 'Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}

header_login = {
    'User-Agent': 'Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}

# 签名请求头一定要这个顺序，否则失败
# timestamp是必填的,其它三个随便填,不要为none即可
header_for_sign = {
    'platform': '',
    'timestamp': '',
    'dId': '',
    'vName': ''
}

# 签到url
sign_url = "https://zonai.skland.com/api/v1/game/attendance"
# 绑定的角色url
binding_url = "https://zonai.skland.com/api/v1/game/player/binding"

# 使用认证代码获得cred
cred_code_url = "https://zonai.skland.com/api/v1/user/auth/generate_cred_by_code"
# 使用token获得认证代码
grant_code_url = "https://as.hypergryph.com/user/oauth2/v2/grant"

app_code = '4ca99fa6b56cc2ba'
config_file = f'{os.path.dirname(__file__)}/config.ini'
CONFIG_SECTION = 'SKYLAND'
secrets_to_check = [
    'SC3_SENDKEY',
    'SC3_UID',
    'QMSG_KEY',
    'PUSHPLUS_KEY',
]
config = ConfigParser()
file_read = config.read(config_file, encoding='utf-8')
CONFIG_SECTRETS = {}
for secret in secrets_to_check:
    secret_value = ''
    secret_value = os.environ.get(secret, '').strip()
    if not os.environ.get(secret):
        if file_read:
            try:
                secret_value = config.get(CONFIG_SECTION, secret, fallback='').strip()
            except (NoSectionError, NoOptionError):
                pass
            except Exception as e:
                logging.error(f'读取配置文件时发生错误: {e!r}')
    CONFIG_SECTRETS[secret] = secret_value

sign_token = threading.local()

def push_serverchan3(sendkey: str, title: str, desp: str = "",
                     uid: Optional[str] = None, tags: Optional[str] = None,
                     short: Optional[str] = None, timeout: int = 10) -> Tuple[bool, str]:
    """
    推送到 Server酱³
    - sendkey: 你的 SendKey（形如 sctp123456tXXXX...）
    - uid: 可选；不填则自动从 sendkey 提取（正则 ^sctp(\\d+)t）
    - title/desp: 标题与正文（desp 支持 Markdown）
    - tags/short: 可选
    返回: (是否成功, 返回文本)
    """
    sendkey = CONFIG_SECTRETS.get('SC3_SENDKEY', '')
    sendkey = sendkey.strip()
    if not sendkey:
        return False, "sendkey is empty"

    if uid is None or uid == '':
        m = re.match(r"^sctp(\d+)t", sendkey)
        print(f"[SC3] 从 sendkey 中提取 uid，结果: {m.group(1) if m else '未提取到'}")
        if not m:
            return False, "cannot extract uid from sendkey; please pass uid explicitly"
        uid = m.group(1)
    if uid:
        uid = uid.strip()
        api = f"https://{uid}.push.ft07.com/send/{sendkey}.send"

    payload = {
        "title": title or "通知",
        "desp": desp or "",
    }
    if tags:
        payload["tags"] = tags
    if short:
        payload["short"] = short

    try:
        r = requests.post(api, json=payload, timeout=timeout)
        ok = (r.status_code == 200)
        return ok, r.text
    except Exception as e:
        return False, f"exception: {e!r}"

def generate_signature(token: str, path, body_or_query):
    """
    获得签名头
    接口地址+方法为Get请求？用query否则用body+时间戳+ 请求头的四个重要参数（dId，platform，timestamp，vName）.toJSON()
    将此字符串做HMAC加密，算法为SHA-256，密钥token为请求cred接口会返回的一个token值
    再将加密后的字符串做MD5即得到sign
    :param token: 拿cred时候的token
    :param path: 请求路径（不包括网址）
    :param body_or_query: 如果是GET，则是它的query。POST则为它的body
    :return: 计算完毕的sign
    """
    t = str(int(time.time()) - 2)
    token = token.encode('utf-8')
    header_ca = json.loads(json.dumps(header_for_sign))
    header_ca['timestamp'] = t
    header_ca_str = json.dumps(header_ca, separators=(',', ':'))
    s = path + body_or_query + t + header_ca_str
    hex_s = hmac.new(token, s.encode('utf-8'), hashlib.sha256).hexdigest()
    md5 = hashlib.md5(hex_s.encode('utf-8')).hexdigest().encode('utf-8').decode('utf-8')
    logging.info(f'算出签名: {md5}')
    return md5, header_ca


def get_sign_header(url: str, method, body, old_header):
    h = json.loads(json.dumps(old_header))
    p = parse.urlparse(url)
    if method.lower() == 'get':
        h['sign'], header_ca = generate_signature(sign_token.token, p.path, p.query)
    else:
        h['sign'], header_ca = generate_signature(sign_token.token, p.path, json.dumps(body))
    for i in header_ca:
        h[i] = header_ca[i]
    return h


def copy_header(cred):
    v = json.loads(json.dumps(header))
    v['cred'] = cred
    return v


def login_by_token(token_code):
    try:
        t = json.loads(token_code)
        token_code = t['data']['content']
    except:
        pass
    grant_code = get_grant_code(token_code)
    return get_cred(grant_code)


def get_cred(grant):
    resp = requests.post(cred_code_url, json={
        'code': grant,
        'kind': 1
    }, headers=header_login).json()
    if resp['code'] != 0:
        raise Exception(f'获得cred失败：{resp["messgae"]}')
    sign_token.token = resp['data']['token']
    return resp['data']['cred']


def get_grant_code(token):
    resp = requests.post(grant_code_url, json={
        'appCode': app_code,
        'token': token,
        'type': 0
    }, headers=header_login).json()
    if resp['status'] != 0:
        raise Exception(f'使用token: {token} 获得认证代码失败：{resp["msg"]}')
    return resp['data']['code']


def get_binding_list(cred):
    v = []
    resp = requests.get(url=binding_url, headers=get_sign_header(binding_url, 'get', None, copy_header(cred))).json()
    if resp['code'] != 0:
        logging.error(f"请求角色列表出现问题：{resp['message']}")
        if resp.get('message') == '用户未登录':
            logging.error(f'用户登录可能失效了，请重新登录！')
            return v
    for i in resp['data']['list']:
        if i.get('appCode') != 'arknights':
            continue
        v.extend(i.get('bindingList'))
    return v


def do_sign(cred):
    characters = get_binding_list(cred)
    all_logs = []
    config = ConfigParser()
    file_read = config.read(config_file, encoding='utf-8')
    
    for i in characters:
        body = {
            'uid': i.get('uid'),
            'gameId': 1
        }
        resp = requests.post(sign_url, headers=get_sign_header(sign_url, 'post', body, copy_header(cred)),
                             json=body).json()
        if resp['code'] != 0:
            logging.error(f'角色{i.get("nickName")}({i.get("channelName")})签到失败了！原因：{resp.get("message")}')
            msg = f'角色{i.get("nickName")}({i.get("channelName")})签到失败了！原因：{resp.get("message")}'
            print(msg)
            all_logs.append(msg)
            continue
        awards = resp['data']['awards']
        for j in awards:
            res = j['resource']
            logging.info(
                f'角色{i.get("nickName")}({i.get("channelName")})签到成功，获得了{res["name"]}×{res.get("count") or 1}'
            )
            msg = f'角色{i.get("nickName")}({i.get("channelName")})签到成功，获得了{res["name"]}×{res.get("count") or 1}'
            all_logs.append(msg)
            print("签到完成！")

    # === Server酱³ 推送（可选，通过环境变量控制） ===
    # 在本地或 GitHub Actions 设置：
    #   SC3_SENDKEY: 必填
    #   SC3_UID: 可选（若不设，将自动从 sendkey 中提取）
    sc3_sendkey = CONFIG_SECTRETS.get('SC3_SENDKEY')
    sc3_uid     = CONFIG_SECTRETS.get('SC3_UID') or None

    if sc3_sendkey:
        # 标题带日期；正文多行
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        # 给 Server酱³ 的 desp，支持 Markdown，这里简单用换行拼接
        desp = '\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        ok, resp = push_serverchan3(sc3_sendkey, title, desp, uid=sc3_uid)
        print("[SC3] 推送成功" if ok else "[SC3] 推送失败", resp)
    else:
        print("[SC3] 跳过推送：未设置环境变量 SC3_SENDKEY")

    # === Qmsg 推送（可选，通过环境变量控制） ===
    # 在本地或云函数环境设置：
    #   QMSG_KEY: 必填
    # 若不设，则尝试从配置文件读取
    # 配置文件格式参考 config.ini
    #   [DEFAULT]
    #   QMSG_KEY=your_key_here
    # 若仍未设，则跳过推送

    QMSG_KEY = CONFIG_SECTRETS.get('QMSG_KEY')
    #云函数环境可使用配置文件
    if QMSG_KEY:
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        desp = '\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        api = f'https://qmsg.zendee.cn/jsend/{QMSG_KEY}'
        payload = {
            "msg": f"{title}\n{desp}",
            "qq": "",  # 指定QQ/QQ群
            "bot": "", # 指定bot
        }
        #print(f"{title}\n{desp}")  # 本地打印推送内容
        try:
            r = requests.post(api, json=payload, timeout=10)
            if r.status_code == 200:
                print("[Qmsg] 推送成功", r.text)
            else:
                print("[Qmsg] 推送失败", r.text)
        except Exception as e:
            print(f"[Qmsg] 推送异常: {e!r}")
    else:
        print("[Qmsg] 跳过推送：未设置环境变量 QMSG_KEY")

    # === PushPlus 推送（可选，通过环境变量控制） ===
    # 在本地或云函数环境设置：
    #   PUSHPLUS_KEY: 必填
    # 若不设，则尝试从配置文件读取
    # 配置文件格式参考 config.ini
    #   [DEFAULT]
    #   PUSHPLUS_KEY=your_key_here
    # 若仍未设，则跳过推送
    PUSHPLUS_KEY = CONFIG_SECTRETS.get('PUSHPLUS_KEY')
    if PUSHPLUS_KEY :
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        content = '\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        api = 'http://www.pushplus.plus/send'
        payload = {
            "token": PUSHPLUS_KEY,
            "title": title,
            "content": content,
            "topic": "",  # 指定topic
            "template": "html"
        }
        #print(f"{title}\n{content}")  # 本地打印推送内容
        try:
            r = requests.post(api, json=payload, timeout=10)
            if r.status_code == 200:
                print("[PushPlus] 推送成功", r.text)
            else:
                print("[PushPlus] 推送失败", r.text)
        except Exception as e:
            print(f"[PushPlus] 推送异常: {e!r}")
    else: 
        print("[PushPlus] 跳过推送：未设置环境变量 PUSHPLUS_KEY")
    return