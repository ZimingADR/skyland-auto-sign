import hashlib
import hmac
import json
import logging
import os.path
import threading
import time
import re
from typing import Optional, Tuple
from datetime import date
from getpass import getpass
from urllib import parse
from configparser import ConfigParser, NoSectionError, NoOptionError

import requests

from SecuritySm import get_d_id

config_file = 'config.ini'
token_save_name = 'TOKEN.txt'
app_code = '4ca99fa6b56cc2ba'
token_env = os.environ.get('TOKEN')
# 现在想做什么？
current_type = os.environ.get('SKYLAND_TYPE')
CONFIG_SECTION = 'SKYLAND'
secrets_to_check = [
    'SC3_SENDKEY',
    'SC3_UID',
    'QMSG_KEY',
    'PUSHPLUS_KEY',
    'FEISHU_WEBHOOK', # 新增这一行
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

http_local = threading.local()
header = {
    'cred': '',
    'User-Agent': 'Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close'
}
header_login = {
    'User-Agent': 'Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0',
    'Accept-Encoding': 'gzip',
    'Connection': 'close',
    'dId': get_d_id()
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
# 验证码url
login_code_url = "https://as.hypergryph.com/general/v1/send_phone_code"
# 验证码登录
token_phone_code_url = "https://as.hypergryph.com/user/auth/v2/token_by_phone_code"
# 密码登录
token_password_url = "https://as.hypergryph.com/user/auth/v1/token_by_phone_password"
# 使用token获得认证代码
grant_code_url = "https://as.hypergryph.com/user/oauth2/v2/grant"
# 使用认证代码获得cred
cred_code_url = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code"


def config_logger():
    current_date = date.today().strftime('%Y-%m-%d')
    if not os.path.exists('logs'):
        os.mkdir('logs')
    logger = logging.getLogger()

    file_handler = logging.FileHandler(f'./logs/{current_date}.log', encoding='utf-8')
    logger.addHandler(file_handler)
    logging.getLogger().setLevel(logging.DEBUG)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    def filter_code(text):
        filter_key = ['code', 'cred', 'token']
        try:
            j = json.loads(text)
            if not j.get('data'):
                return text
            data = j['data']
            for i in filter_key:
                if i in data:
                    data[i] = '*'
            return json.dumps(j, ensure_ascii=False)
        except:
            return text

    _get = requests.get
    _post = requests.post

    def get(*args, **kwargs):
        response = _get(*args, **kwargs)
        logger.info(f'GET {args[0]} - {response.status_code} - {filter_code(response.text)}')
        return response

    def post(*args, **kwargs):
        response = _post(*args, **kwargs)
        logger.info(f'POST {args[0]} - {response.status_code} - {filter_code(response.text)}')
        return response

    # 替换 requests 中的方法
    requests.get = get
    requests.post = post

def push_serverchan3(sendkey: str, title: str, desp: str = "",
                     uid: Optional[str] = None, tags: Optional[str] = None,
                     short: Optional[str] = None, timeout: int = 10) -> Tuple[bool, str]:
    """
    推送到 Server酱³
    - sendkey: 你的 SendKey（形如 sctp123456tXXXX...）
    - uid: 可选；不填则自动从 sendkey 提取（正则 ^sctp(\d+)t）
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
    
    print(f"[SC3] 推送接口: {api}")
    payload = {
        "title": title or "通知",
        "desp": desp or "",
    }
    if tags:
        payload["tags"] = tags
    if short:
        payload["short"] = short

    try:
        r = requests.post(api, json=payload, timeout=10)
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
    # 总是说请勿修改设备时间，怕不是yj你的服务器有问题吧，所以这里特地-2
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


def get_sign_header(url: str, method, body, h):
    p = parse.urlparse(url)
    if method.lower() == 'get':
        h['sign'], header_ca = generate_signature(http_local.token, p.path, p.query)
    else:
        h['sign'], header_ca = generate_signature(http_local.token, p.path, json.dumps(body))
    for i in header_ca:
        h[i] = header_ca[i]
    return h


def login_by_code():
    phone = input('请输入手机号码：')
    resp = requests.post(login_code_url, json={'phone': phone, 'type': 2}, headers=header_login).json()
    if resp.get("status") != 0:
        raise Exception(f"发送手机验证码出现错误：{resp['msg']}")
    code = input("请输入手机验证码：")
    r = requests.post(token_phone_code_url, json={"phone": phone, "code": code}, headers=header_login).json()
    return get_token(r)


def login_by_token():
    token_code = input("请输入（登录森空岛电脑官网后请访问这个网址：https://web-api.skland.com/account/info/hg）:")
    return parse_user_token(token_code)


def parse_user_token(t):
    try:
        t = json.loads(t)
        return t['data']['content']
    except:
        pass
    return t


def login_by_password():
    phone = input('请输入手机号码：')
    password = getpass('请输入密码(不会显示在屏幕上面)：')
    r = requests.post(token_password_url, json={"phone": phone, "password": password}, headers=header_login).json()
    return get_token(r)


def get_cred_by_token(token):
    grant_code = get_grant_code(token)
    return get_cred(grant_code)


def get_token(resp):
    if resp.get('status') != 0:
        raise Exception(f'获得token失败：{resp["msg"]}')
    return resp['data']['token']


def get_grant_code(token):
    response = requests.post(grant_code_url, json={
        'appCode': app_code,
        'token': token,
        'type': 0
    }, headers=header_login)
    resp = response.json()
    if response.status_code != 200:
        raise Exception(f'获得认证代码失败：{resp}')
    if resp.get('status') != 0:
        raise Exception(f'获得认证代码失败：{resp["msg"]}')
    return resp['data']['code']


def get_cred(grant):
    resp = requests.post(cred_code_url, json={
        'code': grant,
        'kind': 1
    }, headers=header_login).json()
    if resp['code'] != 0:
        raise Exception(f'获得cred失败：{resp["message"]}')
    return resp['data']


def get_binding_list():
    v = []
    resp = requests.get(binding_url, headers=get_sign_header(binding_url, 'get', None, http_local.header)).json()
    if resp['code'] != 0:
        print(f"请求角色列表出现问题：{resp['message']}")
        if resp.get('message') == '用户未登录':
            print(f'用户登录可能失效了，请重新运行此程序！')
            os.remove(token_save_name)
            return []
    for i in resp['data']['list']:
        if i.get('appCode') != 'arknights':
            continue
        v.extend(i.get('bindingList'))
    return v

def list_awards(game_id, uid):
    resp = requests.get(sign_url, headers=http_local.header, params={'gameId': game_id, 'uid': uid}).json()
    print(resp)

def do_sign(cred_resp):
    http_local.token = cred_resp['token']
    http_local.header = header.copy()
    http_local.header['cred'] = cred_resp['cred']
    characters = get_binding_list()

    logs_out = []  # 新增：用于 Server酱³ 的汇总文本

    for i in characters:
        body = {
            'gameId': 1,
            'uid': i.get('uid')
        }
        resp = requests.post(sign_url, headers=get_sign_header(sign_url, 'post', body, http_local.header),
                             json=body).json()
        
        # === 修改处：处理名字，去掉#nnnn，去掉服务器名 ===
        # 原名形如: "神奇的神烦狗#7480"
        raw_nick_name = i.get('nickName', '')
        # 如果包含#，则分割取第一部分，否则直接用原名
        nick_name = raw_nick_name.split('#')[0] if '#' in raw_nick_name else raw_nick_name
        
        # 提取角色基本信息，加粗名字（如果平台支持Markdown），不含(官服)
        char_info = f"👤 **{nick_name}**"

        if resp['code'] != 0:
            # 失败情况：使用❌图标，并换行缩进
            msg = f"{char_info}\n   ❌ 签到失败：{resp.get('message')}"
            print(msg)
            logs_out.append(msg)
            continue
        
        awards = resp['data']['awards']
        for j in awards:
            res = j['resource']
            # 成功情况：使用✅图标，并换行缩进
            msg = f"{char_info}\n   ✅ 签到成功：获得 {res['name']}×{j.get('count') or 1}"
            print(msg)
            logs_out.append(msg)

    return logs_out  # 新增：返回给调用方

def save(token):
    with open(token_save_name, 'w') as f:
        f.write(token)
    print(
        f'您的鹰角网络通行证保存在{token_save_name}, 打开这个可以把它复制到云函数服务器上执行!\n双击添加账号即可再次添加账号')


def read(path):
    if not os.path.exists(token_save_name):
        return []
    v = []
    with open(path, 'r', encoding='utf-8') as f:
        for i in f.readlines():
            i = i.strip()
            i and i not in v and v.append(i)
    return v


def read_from_env():
    v = []
    token_list = token_env.split(',')
    for i in token_list:
        i = i.strip()
        if i and i not in v:
            v.append(parse_user_token(i))
    print(f'从环境变量中读取到{len(v)}个token...')
    return v


def init_token():
    if token_env:
        print('使用环境变量里面的token')
        # 对于github action,不需要存储token,因为token在环境变量里
        return read_from_env()
    tokens = []
    tokens.extend(read(token_save_name))
    add_account = current_type == 'add_account'
    if add_account:
        print('！！！您启用了添加账号模式，将不会签到！！！')
    if len(tokens) == 0 or add_account:
        tokens.append(input_for_token())
    save('\n'.join(tokens))
    return [] if add_account else tokens


def input_for_token():
    print("请输入你需要做什么：")
    print("1.使用用户名密码登录（非常推荐）")
    print("2.使用手机验证码登录（非常推荐，但可能因为人机验证失败）")
    print("3.手动输入鹰角网络通行证账号登录(推荐)")
    mode = input('请输入（1，2，3）：')
    if mode == '' or mode == '1':
        token = login_by_password()
    elif mode == '2':
        token = login_by_code()
    elif mode == '3':
        token = login_by_token()
    else:
        exit(-1)
    return token

def start():
    token = init_token()
    all_logs = []  # 新增：汇总所有账号/角色的输出
    config = ConfigParser()
    file_read = config.read(config_file, encoding='utf-8')

    for i in token:
        try:
            logs_out = do_sign(get_cred_by_token(i))
            all_logs.extend(logs_out)
        except Exception as ex:
            err = f'签到失败，原因：{str(ex)}'
            print(err)
            logging.error('', exc_info=ex)
            all_logs.append(err)

    print("签到完成！")

    # === Server酱³ 推送（可选，通过环境变量控制） ===
    sc3_sendkey = CONFIG_SECTRETS.get('SC3_SENDKEY', '')
    sc3_uid = CONFIG_SECTRETS.get('SC3_UID', '')
    if sc3_sendkey:
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        desp = '\n\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        ok, resp = push_serverchan3(sc3_sendkey, title, desp, uid=sc3_uid)
        print("[SC3] 推送成功" if ok else "[SC3] 推送失败", resp)
    else:
        print("[SC3] 跳过推送：未设置环境变量 SC3_SENDKEY")

    # === Qmsg 推送 ===
    QMSG_KEY = CONFIG_SECTRETS.get('QMSG_KEY', '')
    if QMSG_KEY:
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        desp = '\n\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        api = f'https://qmsg.zendee.cn/jsend/{QMSG_KEY}'
        payload = {
            "msg": f"{title}\n{desp}",
            "qq": "",  # 指定QQ/QQ群
            "bot": "", # 指定bot
        }
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

    # === PushPlus 推送 ===
    PUSHPLUS_KEY = CONFIG_SECTRETS.get('PUSHPLUS_KEY', '')
    if PUSHPLUS_KEY :
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        content = '\n\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        api = 'http://www.pushplus.plus/send'
        payload = {
            "token": PUSHPLUS_KEY,
            "title": title,
            "content": content,
            "topic": "",  # 指定topic
            "template": "html"
        }
        try:
            r = requests.post(api, json=payload, timeout=10)
            resp = r.json()
            if resp.get('code') == 200:
                print("[PushPlus] 推送成功", resp)
            else:
                print("[PushPlus] 推送失败", resp)
        except Exception as e:
            print(f"[PushPlus] 推送异常: {e!r}")
    else:
        print("[PushPlus] 跳过推送：未设置环境变量 PUSHPLUS_KEY")

    # === 飞书推送 (Feishu/Lark) ===
    FEISHU_WEBHOOK = CONFIG_SECTRETS.get('FEISHU_WEBHOOK', '')
    if FEISHU_WEBHOOK:
        title = f'森空岛自动签到结果 - {date.today().strftime("%Y-%m-%d")}'
        content = '\n\n'.join(all_logs) if all_logs else '今日无可用账号或无输出'
        
        # 使用 interactive 消息卡片以支持 markdown
        payload = {
            "msg_type": "interactive",
            "card": {
                "config": {
                    "wide_screen_mode": True
                },
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": title
                    },
                    "template": "blue"
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": content
                        }
                    }
                ]
            }
        }
        try:
            r = requests.post(FEISHU_WEBHOOK, json=payload, timeout=10)
            resp = r.json()
            if resp.get('code') == 0:
                print("[飞书] 推送成功", resp)
            else:
                print("[飞书] 推送失败", resp)
        except Exception as e:
            print(f"[飞书] 推送异常: {e!r}")
    else:
        print("[飞书] 跳过推送：未设置环境变量 FEISHU_WEBHOOK")


if __name__ == '__main__':
    print('本项目源代码仓库：https://github.com/xxyz30/skyland-auto-sign(已被github官方封禁)')
    print('https://gitee.com/FancyCabbage/skyland-auto-sign')
    config_logger()

    logging.info('=========starting==========')

    start_time = time.time()
    start()
    end_time = time.time()
    logging.info(f'complete with {(end_time - start_time) * 1000} ms')
    logging.info('===========ending============')
