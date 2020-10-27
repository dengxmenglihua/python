# 字符串前面加b，r，u的含义
## 加b
作用：python3.x里默认的str是(py2.x里的)unicode, bytes是(py2.x)的str, b”“前缀代表的就是bytes 
　　　python2.x里, b前缀没什么具体意义， 只是为了兼容python3.x的这种写法

b" "前缀表示：后面字符串是bytes 类型。
用处：
网络编程中，服务器和浏览器只认bytes 类型数据。
如：send 函数的参数和 recv 函数的返回值都是 bytes 类型
附：
在 Python3 中，bytes 和 str 的互相转换方式是
str.encode('utf-8')
bytes.decode('utf-8')

## 加r
作用：声明后面的字符串是普通字符串，相对的，特殊字符串中含有：转义字符 \n \t 什么什么的，也就是对所有字符以文本输出。

## 加u
作用：后面字符串以 Unicode 格式 进行编码，一般用在中文字符串前面，防止因为源码储存格式问题，导致再次使用时出现乱码。
也就是防止汉语显示不出来。