#!/usr/bin/env python
# encoding: utf-8
import hashlib
import http.cookiejar
from collections import OrderedDict
from urllib.parse import parse_qs, urlparse

import requests
import base64, rsa, binascii
import time, re, json, random

import sys

from os.path import getsize


class Weibo(object):
    '''
    weibo class:
       - login
       - upload picture
       - upload video
    '''

    def __init__(self, username="", passwd="", proxy=False):
        self.r = requests.Session()
        self.r.cookies = http.cookiejar.LWPCookieJar('weibo_cookies.txt')
        if proxy:
            self.r.proxies = {
                'http': 'socks5://127.0.0.1:1080',
                'https': 'socks5://127.0.0.1:1080',
            }
        self.username = username
        self.passwd = passwd
        self.weibo_url = 'http://weibo.com/'
        self.prelogin_url = 'https://login.sina.com.cn/sso/prelogin.php'
        self.login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'}
        self.headers2 = {
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'http://weibo.com',
            'Referer': 'http://weibo.com/?topnav=1&wvr=6&mod=logo',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'}
        self.init_url = 'http://multimedia.api.weibo.com/2/multimedia/init.json'
        self.upload_url = 'http://multimedia.api.weibo.com/2/multimedia/upload.json'
        self.uppic_url = 'http://picupload.service.weibo.com/interface/pic_upload.php'
        self.stup_url = 'http://weibo.com/aj/mblog/add'
        # self.stup_url = 'http://m.weibo.cn/aj/mblog/add'
        pass

    def is_login(self):
        """判断是否登录成功
        :return: 登录成功返回True，失败返回False
        """
        try:
            self.r.cookies.load(ignore_discard=True, ignore_expires=True)
        except:
            print(u"没有检测到cookie文件")
            return False
        url = "http://weibo.com/"
        my_page = self.r.get(url, headers=self.headers)

        if "我的首页" in my_page.text:
            return True
        else:
            return False

    def login(self):
        '''
        '''
        self.prelogin()
        self.sp = self.getPwd()
        para = {
            "encoding": "UTF-8",
            "entry": "weibo",
            "from": "",
            "gateway": 1,
            "nonce": self.nonce,
            "pagerefer": "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl%3D%252F",
            "prelt": 117,
            "pwencode": "rsa2",
            "returntype": "TEXT",
            "rsakv": self.rsakv,
            "savestate": 0,
            "servertime": self.servertime,
            "service": "miniblog",
            "sp": self.sp,
            "sr": "1920*1080",
            "su": self.su,
            "url": "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "useticket": 1,
            "vsnf": 1,
        }

        if self.showpin == 1:
            self.getPin()
            vcode = input('input vcode:')
            para['door'] = vcode
            para['cdult'] = 2
            para['pcid'] = self.pcid
            para['prelt'] = 2041

        data = self.r.post(self.login_url, data=para, headers=self.headers)
        data = json.loads(data.text)
        if data['retcode'] != "0":
            return False, data['reason']
        self.ticket = data['ticket']
        para = {
            'callback': 'sinaSSOController.callbackLoginStatus',
            'ticket': self.ticket,
            'client': 'ssologin.js(v1.4.18)',
            'retcode': 0,
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack&sudaref=weibo.com'
        }
        self.r.get('http://passport.weibo.com/wbsso/login', params=para, headers=self.headers)
        self.r.get(para['url'], headers=self.headers)
        interest = self.r.get('http://weibo.com/nguide/interest')
        uid = re.search(r"CONFIG\['uid'\]='([^']+)'", interest.text).group(1)
        nick = re.search(r"CONFIG\['nick'\]='([^']+)'", interest.text).group(1)
        self.r.cookies.save(ignore_discard=True, ignore_expires=True)
        return True, uid, nick

    def getPin(self):
        '''
        验证码
        '''
        para = {
            'p': self.pcid,
            'r': random.randint(10000, 100000),
            's': 0
        }
        pic = self.r.get('http://login.sina.com.cn/cgi/pin.php', params=para, headers=self.headers)
        open('pin.png', 'wb').write(pic.content)

    def prelogin(self):
        '''
        prelogin process
        '''
        self.r.get(self.weibo_url)
        self.su = self.getSu()
        para = {
            "_": time.time(),
            "callback": "sinaSSOController.preloginCallBack",
            "checkpin": 1,
            "client": "ssologin.js(v1.4.18)",
            "entry": "weibo",
            "rsakt": "mod",
            "su": self.su
        }
        d = self.r.get(self.prelogin_url, params=para, headers=self.headers).text
        data = re.findall(r'preloginCallBack\(([\w\W]+?)\)', d)[0]
        data = json.loads(data)
        self.servertime = data.get('servertime', '')
        self.nonce = data.get('nonce', '')
        self.pubkey = data.get('pubkey', '')
        self.rsakv = data.get('rsakv', '')
        self.showpin = data.get('showpin', 0)
        self.pcid = data.get('pcid', '')

    def getSu(self):
        '''
        获取加密用户名: 只有 Base64
        '''
        return base64.encodebytes(self.username.encode("utf-8"))[:-1]

    def getPwd(self):
        '''
        获取加密密码sp
        '''
        rsaPubkey = int(self.pubkey, 16)
        RSAKey = rsa.PublicKey(rsaPubkey, 65537)  # 创建公钥
        codeStr = str(self.servertime) + '\t' + str(self.nonce) + '\n' + str(self.passwd)
        pwd = rsa.encrypt(codeStr.encode("utf-8"), RSAKey)  # 使用rsa进行加密
        return binascii.b2a_hex(pwd)  # 将加密信息转换为16进制。

    def getUniqueKey(self):
        return str(int(time.time() * 1000)) + str(random.randint(0, 99))

    def _CalcMD5(self, file):
        md5obj = hashlib.md5()
        md5obj.update(file)
        hash = md5obj.hexdigest()

        return hash

    def post_data(self, filetoken, startloc, file):
        para = {
            'source': 2637646381,
            'filetoken': filetoken,
            'sectioncheck': self._CalcMD5(file),
            'startloc': startloc,
            'client': 'web',
            'status': 'wired',
            'ua': self.headers['User-Agent'],
            'v': self.getUniqueKey(),
        }
        res = self.r.post(self.upload_url, params=para, data=file)

        res = res.json()
        try:
            return res['succ']
        except:
            try:
                return res['fid']
            except:
                return None

    def upload_init(self, filename):
        with open(filename, 'rb') as f:
            para = {
                "length": getsize(filename),
                "check": self._CalcMD5(f.read()),
                "type": 'video',
                "source": 2637646381,
                "name": filename,
                'client': 'web',
                'mediaprops': '{"screenshot": 0}',
                "status": 'wired',
                "ua": self.r.headers['User-Agent'],
                "count": 1
            }
        res = self.r.post(self.init_url, params=para)

        return res.json()

    def upload_video(self, filename):
        init_info = self.upload_init(filename)
        fileToken = init_info['fileToken']
        chunk_size = init_info['length']
        with open(filename, 'rb') as f:
            startloc = 0
            while True:
                chunk = f.read(chunk_size * 1024)
                flag = self.post_data(fileToken, startloc, chunk)
                startloc += chunk_size * 1024
                if flag is True:
                    continue
                else:
                    if flag is not None:
                        return flag

    def upload_pic(self, filename):
        para = {
            'cb': "http://weibo.com/aj/static/upimgback.html?_wv=5&callback=STK_ijax_" + self.getUniqueKey() + "21",
            'mime': 'image/jpeg',
            'data': 'base64',
            'url': 0,
            'markpos': 1,
            'logo': "",
            'nick': 0,
            'marks': 1,
            'app': 'miniblog',
            's': 'rdxt'
        }

        with open(filename, 'rb') as f:
            data = {'b64_data': base64.b64encode(f.read())}

            res = self.r.post(self.uppic_url, params=para, data=data)

            return parse_qs(urlparse(res.url).query)['pid'][0]

    def update_status(self, text, videoname, picname, categorie="其他", title="", tags=None):
        fid = self.upload_video(videoname)
        pic = self.upload_pic(picname)

        data = OrderedDict([
            ('location', 'v6_content_home'),
            ('text', text), (
                'appkey', ""),
            ('style_type', 1), (
                'pic_id', ""), (
                'pdetail', ""), (
                'video_fid', fid), (
                'video_titles', 'very good'), (
                'video_categories', categorie), (
                'video_tags', "" if tags is None else "|".join(tags)), (
                'video_covers', "http://wx2.sinaimg.cn/large/" + pic + ".jpg|501|282"), (
                'video_monitor', 0), (
                'rank', 0), (
                'rankid', ""), (
                'module', 'stissue'), (
                'pub_source', 'main_'), (
                'pub_type', 'dialog'), (
                '_t', 0)
        ])
        para = OrderedDict([
            ('ajwvr', 6),
            ('__rnd', int(time.time() * 1000))
        ])

        res = self.r.post(self.stup_url, data=data, params=para, allow_redirects=True, headers=self.headers2)
        res = res.json()
        if res['code'] == '100000':
            print("发送成功")
        else:
            print(res['msg'])

def login(username, passwd):
    '''
    登录
    '''
    weibo = Weibo(username, passwd)
    if(weibo.is_login()):
        return weibo
    else:
        weibo.login()
        return weibo


