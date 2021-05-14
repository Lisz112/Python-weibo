from urllib.request import urlopen, HTTPCookieProcessor, build_opener, Request
from bs4 import BeautifulSoup
import json
import requests, pickle
import time
from urllib.parse import quote_plus
import base64
import hashlib
import rsa
import binascii
import urllib.parse
import os
import http.cookiejar
import time
import pdb, traceback, sys
import re
import xlwt

def debug(func):
    def wrap(*arg, **kwarg):
        try:
            return func(*arg, **kwarg)
        except:
            type, value, tb = sys.exc_info()
            traceback.print_exc()
            pdb.post_mortem(tb)
    return wrap

class UserInfo():
    def __init__(self, userId, userName, area, gender):
        self.userId = userId
        self.userName = userName
        self.area = area
        self.gender = gender

class Comment():
    def __init__(self, comment, createdTime):
        self.comment = comment
        self.createdTime = createdTime
        self.userInfo = None

    def set_userInfo(self, userInfo):
        self.userInfo = userInfo

    def get_userArea(self):
        return self.userInfo.area

    def get_userName(self):
        return self.userInfo.userName

    def get_comment(self):
        return self.comment

    def get_createdTime(self):
        return self.createdTime

    def get_userId(self):
        return self.userInfo.userId

class Weibo():
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36'
        self.session = requests.session()
        self.cookie_file = './cookie'

    def get_su(self):
        username_quote = quote_plus(self.username)
        username_base64 = base64.b64encode(username_quote.encode("utf-8"))
        return username_base64.decode("utf-8")

    # 预登陆获得 servertime, nonce, pubkey, rsakv
    def get_server_data(self, su):
        referer = 'https://login.sina.com.cn/signup/signin.php?entry=sso' # 注意必须加在请求头上，不然报错
        headers = {'User-Agent': self.agent, 'Referer': referer}

        pre_url = "https://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su="
        pre_url = pre_url + su + "&rsakt=mod&client=ssologin.js(v1.4.15)&_="
        pre_url = pre_url + getTimeStamp()
        pre_data_res = self.session.get(pre_url, headers=headers)

        sever_data = eval(
            pre_data_res.content.decode("utf-8").replace(
                "sinaSSOController.preloginCallBack", ''))
        return sever_data

    def get_password(self, pubkey, servertime, nonce):
        string = (str(servertime) + "\t" + str(nonce) + "\n" + str(self.password)).encode("utf-8")
        public_key = rsa.PublicKey(int(pubkey, 16), int("10001", 16))
        password = rsa.encrypt(string, public_key)
        password = binascii.b2a_hex(password)
        return password.decode()

    def get_token(self, res):
        content = json.loads(res.text)
        protection_url = content['protection_url']
        protection_url_unquote = urllib.parse.unquote(protection_url)
        index_of_token = protection_url_unquote.find('token=')
        token = protection_url_unquote[index_of_token+6:]
        return token


    # tpye: 1短信验证，2私信验证
    def login(self, type):
        su = self.get_su()
        sever_data = self.get_server_data(su)
        nonce = sever_data['nonce']
        servertime = sever_data['servertime']
        rsakv = sever_data['rsakv']
        pubkey = sever_data['pubkey']
        sp = self.get_password(pubkey, servertime, nonce)

        post_data={
            'entry': 'sso',
            'gateway': '1',
            'from': '',
            'savestate': 30,
            'useticket': 0,
            'pagerefer': 'http://login.sina.com.cn/',
            'vsnf': 1,
            'su': su,
            'service': 'sso',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': sp,
            'sr': '1920*1080',
            'encoding': 'UTF-8',
            'cdult': 3,
            'domain': 'sina.com.cn',
            'prelt': 25,
            'returntype': 'TEXT'
        }
        url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)&_=' + str(int(time.time() * 1000))
        headers = {
            'Referer': 'https://login.sina.com.cn/signup/signin.php?entry=sso',
            'User-Agent': self.agent,
            'Host': 'login.sina.com.cn'
        }
        # 发送post请求进行登录
        post_data_res = self.session.post(url, data=post_data, headers=headers)

        # 进行验证
        # 获取token
        token = self.get_token(post_data_res)

        retcode = -1 # 记录返回情况
        msg = ''
        redirect_url = ''
        # 短信验证码登录
        if type==1:
            # 发送get请求，并解析结果，获得加密后的电话号码
            protection_url = 'https://login.sina.com.cn/protection/index?callback_url=http://login.sina.com.cn/&token=' + token
            protection_url_res = self.session.get(protection_url).text
            protection_url_res_bs = BeautifulSoup(protection_url_res, 'html.parser')
            encrypt_mobile = protection_url_res_bs.find(id='ss0').get('value')

            # 构造发送短信的请求
            send_message_url = 'https://login.sina.com.cn/protection/mobile/sendcode?token=' + token

            referer = "https://login.sina.com.cn/protection/index?token={}&callback_url=http%3A%2F%2Flogin.sina.com.cn%2F".format(token)
            headers = {
                'Referer': referer,
                'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8"
            }

            body = {'encrypt_mobile': encrypt_mobile}
            data = urllib.parse.urlencode(body)
            # 发送验证码到手机
            res = self.session.post(send_message_url, headers = headers, data = data)

            message_code = input('输入短信验证码')

            login_url = 'https://login.sina.com.cn/protection/mobile/confirm?token=' + token
            login_post_data = { 'encrypt_mobile': encrypt_mobile, 'code': message_code}

            login_post_res = self.session.post(login_url, headers = headers, data = login_post_data)
            login_post_res_json = json.loads(login_post_res.text)
            retcode = login_post_res_json.get('retcode')
            msg = login_post_res_json.get('msg')
            redirect_url = login_post_res_json.get('data').get('redirect_url')
        elif type == 2:
            privatemsg_url = 'https://login.sina.com.cn/protection/privatemsg/send'

            body = {'token': token}
            referer = 'https://login.sina.com.cn/protection/index?token={}&callback_url=http%3A%2F%2Flogin.sina.com.cn%2F'.format(token)
            headers = {
                'Referer': referer,
                'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Host': 'login.sina.com.cn',
                'User-Agent': self.agent
            }
            data = urllib.parse.urlencode(body)
            html = requests.post(privatemsg_url, headers=headers, data=data)
            bs = BeautifulSoup(html.text, 'html.parser')
            res_json = json.loads(bs.text)
            retcode = res_json.get('retcode')
            msg = res_json.get('msg')
        if retcode == 20000000:
            # 如果是发送私信验证，需要主动调用接口获得redirect_url
            if (type==2):
                stop = False
                getStatus_url = 'https://login.sina.com.cn/protection/privatemsg/getstatus'
                body = {'token': token}
                data = urllib.parse.urlencode(body)
                count = 0 # 尝试10次
                while (not stop):
                    time.sleep(2) # 每2秒请求一次
                    html = requests.post(getStatus_url, data=data, headers=headers)
                    ret_json = json.loads(html.text)
                    redirect_url = ret_json.get('data').get('redirect_url')
                    count += 1
                    if (redirect_url != '' or count>10):
                        stop = True
                if (redirect_url == ''):
                    print('未能在时间内正确发送私信验证！登陆失败！')
                    return

            # 登陆成功后跳转
            # redirect_html = self.session.get(redirect_url)
            # redirect_html_bs = BeautifulSoup(redirect_html.content.decode('ISO-8859-1'), 'html.parser')
            # location_replace = redirect_html_bs.find('script').contents[0].strip()
            # location_replace_url = location_replace[18:-3]

            # self.session.get(location_replace_url)
            save_cookies_lwp(self.session.cookies, self.cookie_file)
        else:
            print(msg)

    # 获取当前页的评论数据
    def getComment(self, params):
        ajwvr = params[0]
        _from = params[1]
        id = params[2]
        _rnd = getTimeStamp()
        root_comment_max_id = params[4]
        root_comment_max_id_type = params[5]
        root_comment_ext_param = params[6]
        page = params[7]
        filter = params[8]
        sum_comment_number = params[9]
        filter_tips_before = params[10]

        # 构造请求url
        requestsUrl = \
            'https://weibo.com/aj/v6/comment/big?ajwvr={}&id={}&from={}&__rnd={}'.format(ajwvr, id, _from, _rnd)
        if (root_comment_max_id!=''):
            requestsUrl += '&root_comment_max_id={}&root_comment_max_id_type={}&root_comment_ext_param={}&page={}&filter={}&sum_comment_number={}&filter_tips_before={}'.\
                format(root_comment_max_id, root_comment_max_id_type, root_comment_ext_param, page, filter, sum_comment_number, filter_tips_before)

        if (root_comment_max_id==0):
            print('已到尾页！')
            return None

        # 发起请求
        html = weibo.getPage(requestsUrl)
        resJson = None
        try:
            # 若正常返回，则数据为json格式，尝试解析
            resJson = json.loads(html.text)
        except json.decoder.JSONDecodeError as e:
            # 解析失败，尝试登录
            print('返回非json数据，需要登录！')
            # 尝试再次登录 推荐使用私信登录，不显示验证次数
            weibo.login(params[11])
            # 尝试再次获取数据
            html = weibo.getPage(requestsUrl)
            try:
                resJson = json.loads(html.text)
            except json.decoder.JSONDecodeError as e:
                # 若再次登录后，获取数据依旧失败，则直接返回
                print('依旧无法正常解析json数据！')
                return None

        # 若数据异常，尝试再次登录
        if (int(resJson['code'])!=100000):
            print('不能正常返回。msg: {}。尝试登录'.format(resJson['msg']))
            weibo.login(params[11])
            html = weibo.getPage(requestsUrl)
            resJson = json.loads(html.text)
            # 仍然无法正常获取数据，打印并返回
            if (int(resJson['code'])!=100000):
                print('不能正常返回，msg:' + resJson['msg'])
                return None

        # 开始获取当前页数据
        htmlStr = resJson['data']['html']
        bs = BeautifulSoup(htmlStr, 'html.parser')
        comments = self.parseCommentData(bs)

        # 判断是否还有数据可以加载
        comment_loading = bs.find('div', attrs={'node-type':'comment_loading'})
        action_data = None
        if (comment_loading is not None):
            print('comment_loading...')
            # 更新参数
            action_data = proceed_action_data(comment_loading['action-data'])
        else:
            # 尝试查找a标签的action-data
            print('未能找到comment_loading，尝试直接寻找a标签的action-data')
            aList = bs.find_all('a', attrs={'action-data': True})
            if (len(aList)>0):
                action_data = proceed_action_data(aList[len(aList)-1]['action-data'])
            else:
                print('未能找到a标签的action-data')

        if (action_data is not None):
            params[2] = action_data['id']
            params[3] = getTimeStamp()
            params[4] = action_data['root_comment_max_id']
            params[5] = action_data['root_comment_max_id_type']
            params[6] = action_data['root_comment_ext_param']
            params[7] = action_data['page']
            params[8] = action_data['filter']
            params[9] = action_data['sum_comment_number']
            params[10] = action_data['filter_tips_before']
        else:
            print('未能找到action-data！查询结束！')
            params[4] = 0

        return comments

    # 解析评论数据
    # commentData为列表形式，每次请求获得20条评论
    def  parseCommentData(self, bs):
        commentsResult = []# 用于记录最后结果

        # 解析并找到所有一级评论
        comments = bs.find_all('div', attrs={'node-type': re.compile('root_comment')})

        # 依次处理评论
        for comment in comments:
            # 首先找到userId
            WB_text = comment.find('div', attrs={'class': 'WB_text'})
            a = WB_text.find(has_usercard)
            commentText = ''
            commentCreatedTime = ''
            if (a is not None):
                userId = a['usercard'][3:] # 找到userId
                userInfo = self.getUserInfoFromUserObj(userId, a.text)
                commentText = WB_text.text
                timeTag = comment.find('div', class_='WB_from')
                if (timeTag is not None):
                    commentCreatedTime = timeTag.text
                else:
                    print('未能找到评论时间')
                commentObj = Comment(commentText, commentCreatedTime)
                commentObj.set_userInfo(userInfo)
                commentsResult.append(commentObj)
            else :
                print('未能找到用户id，跳过')
                continue

        print('找到{}条评论'.format(len(commentsResult)))
        return commentsResult

    def getUserInfoFromUserObj(self, userId, userName):
        userArea = ''
        url = 'https://weibo.com/u/{}?is_all=1'.format(userId)
        html = self.session.get(url)
        bs = BeautifulSoup(html.text, 'html.parser')

        script = bs.find('script', string=re.compile('"domid":"Pl_Core_UserInfo'))
        if (script is not None):
            userInfo_script = script.contents[0]
            if userInfo_script is not None:
                userInfo_script_str = str(userInfo_script)
                userInfo_json = json.loads(userInfo_script_str[8:-1])
                try:
                    userInfo_html_str = userInfo_json['html']
                    bs = BeautifulSoup(userInfo_html_str, 'html.parser')
                    item_texts = bs.find_all('span', class_='item_text')
                    if len(item_texts)>1:
                        userArea = str.strip(item_texts[1].text)
                except KeyError as e:
                    print(e)
            else:
                print('无法找到包含用户信息的script')
                return None

        userInfo = UserInfo(userId, userName, userArea, 'userGender')
        return userInfo

    # 到用户主页获取用户的地区信息
    def getUserArea(self, userId):
        # 需要注意，手机端的用户主页分3个tab，依次为“主页”，“微博”，“相册”
        # 用户的地区信息在“主页”tab中，但是主页会默认显示“微博”tab，因此需要先获取“主页”的containerId，进而获得用户的地区信息
        # 首先需要获取主页的containerid
        url = 'https://m.weibo.cn/api/container/getIndex?uid={}&type=uid&value={}'.format(userId, userId)
        html = self.session.get(url)
        resJson = json.loads(html.text)
        if resJson['ok']!=1:
            print('获取数据失败！')
            return -1
        tabsInfo = resJson['data']['tabsInfo']
        mainPageContainerId = tabsInfo['tabs'][0]['containerid']
        url = 'https://m.weibo.cn/api/container/getIndex?uid={}&type=uid&value={}&containerid={}'.format(userId, userId, mainPageContainerId)
        htmlMainPage = self.session.get(url)
        resJson = json.loads(htmlMainPage.text)
        if resJson['ok']!=1:
            print('获取数据失败！')
            return -1

        cardGroup = resJson['data']['cards'][0]['card_group']
        for card in cardGroup:
            if card['item_name']=='所在地':
                return card['item_content']

        print('未找到用户{}的所在地信息！'.format(userId))
        return -1

    def getCommentInfoFromCommentObj(self, commentObj):
        createdTime = commentObj['created_at']
        text = commentObj['text']
        comment = Comment(text, createdTime)
        return comment

    def getPage(self, url):
        # 爬取数据之前先尝试使用cookie
        SUB = load_cookies_from_lwp(self.cookie_file)
        headers = {'Host': 'weibo.com', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36'}
        self.session.cookies['SUB'] = SUB

        html = self.session.get(url, headers=headers)
        return html

def proceed_action_data(action_data_str):
    res = {}
    action_datas = str.split(action_data_str, '&')
    for action_data in action_datas:
        list = str.split(action_data, '=')
        res[list[0]] = list[1]
    return res

def has_usercard(tag):
    return tag.has_attr('usercard')

def save_cookies_lwp(cookiejar, filename):
    lwp_cookiejar = http.cookiejar.LWPCookieJar()
    if not os.path.exists(filename):
        file = open(filename,'w')
        # file.write('#LWP-Cookies-2.0')
        file.close()

    # 寻找cookie中的SUB
    for c in cookiejar:
        args = dict(vars(c).items())
        args['rest'] = args['_rest']
        del args['_rest']
        c = http.cookiejar.Cookie(**args)

        if c.name=='SUB':
            SUB = c.value
            file = open(filename, 'w')
            file.truncate()
            file.write(SUB)
            file.close()
            print('cookie已经保存在本地！值为：' + SUB)

def load_cookies_from_lwp(filename):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                SUB = f.read()
                if (len(SUB)>0):
                    return SUB
                else:
                    print('cookie文件为空！')
                    return None
        except http.cookiejar.LoadError as e:
            print(e)
            return None
    else:
        print('cookie file not found')
        return None

# 获取当前时间（毫秒）的Unix时间戳
def getTimeStamp():
    return str(int(time.time() * 1000))

# 将评论内容保存至文件
def save_comments_to_file(comments):
    book = xlwt.Workbook()
    sheet = book.add_sheet(u'sheet1',cell_overwrite_ok=True)
    i=0
    for comment in comments:
        sheet.write(i,0, comment.get_userName())
        sheet.write(i,1, comment.get_comment())
        sheet.write(i,2, comment.get_userArea())
        sheet.write(i,3, comment.get_createdTime())
        sheet.write(i,4, comment.get_userId())
        i+=1
    book.save('comments.xls')

startTime = time.localtime(time.time())
print('start at '+ time.strftime("%Y-%m-%d %H:%M:%S",startTime))

weibo = Weibo('username', 'password')

# 拼接第一次请求的地址
url = 'https://weibo.com/aj/v6/comment/big?ajwvr=6&id=4629927523521329&from=singleWeiBo&__rnd=' + getTimeStamp()

param_ajwvr = '6'
param_from = 'singleWeiBo'
param_id = '4629927523521329' # 上面url中的id
param__rnd = ''

params = [
    param_ajwvr, # ajwvr
    param_from,  # from
    param_id,    # id
    param__rnd,  # 毫秒级时间戳
    '', # root_comment_max_id
    '', # root_comment_max_id_type
    '', # root_comment_ext_param
    '', # page
    '', # filter
    '', # sum_comment_number
    '', # filter_tips_before
    1 # 验证方式 1为短信验证 2为私信验证
] # 分别对应ajwvr, from, id, _rnd， 验证方式 5个参数

comments = []
maxComments = 10000
page = 0 # 尝试获取前n页数据

while (len(comments)<maxComments):
    currentComments = weibo.getComment(params)
    if currentComments is not None:
        comments.extend(currentComments)
    if params[4]==0:
        break

    time.sleep(2)
    print('已经爬取{}条数据'.format(len(comments)))

print('start saving comments at'+ time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())))
save_comments_to_file(comments)

print('end at '+ time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())))
print('over')


