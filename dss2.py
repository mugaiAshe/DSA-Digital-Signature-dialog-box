import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from dss3 import Ui_MainWindow  # 导入 uiDemo4.py 中的 Ui_MainWindow 界面类
import time
from Crypto.Random import random
from Crypto.Util import number
from Crypto.Util.number import *
import sip


def get_q():
    q = number.getPrime(160)
    return q


def get_p(q):
    while (1):
        t = random.randint(2 ** 351, 2 ** 352)
        p = q * t + 1
        if (number.isPrime(p)):
            return p


def get_g(p, q):
    while (1):
        h = random.randrange(1, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            return g


# 获取公钥
def get_y(x, g, p):
    y = pow(g, x, p)
    return y

# 进行签名
def encode(x, p, q, g, m):
    k = random.randrange(0, q)
    # 求k的逆元d
    d = inverse(k, q)

    r = pow(g, k, p) % q

    s = (d * (m + x * r)) % q

    return r, s


# 验证签名
def decode(m, r, s, p, q, g, y):
    w = inverse(s, q)

    u1 = (m * w) % q
    u2 = (r * w) % q

    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v

class MyMainWindow(QMainWindow, Ui_MainWindow):  # 继承 QMainWindow类和 Ui_MainWindow界面类
    def __init__(self, parent=None):
        super(MyMainWindow, self).__init__(parent)  # 初始化父类
        self.setupUi(self)  # 继承 Ui_MainWindow 界面类

    #为对话框MyMainWindow窗体类生成协议的公开参数
    q = get_q()
    p = get_p(q)
    g = get_g(p, q)

    x = random.randrange(0, q)
    y = get_y(x, g, p)

    def encode(self):  # 点击 encode 触发
        t = time.time()

        msg = self.lineEdit.text()#获取输入对话框的文字，即消息明文
        m = number.bytes_to_long(msg.encode('utf-8'))

        r, s = encode(self.x, self.p, self.q, self.g, m)# 进行签名
        temp = time.time()-t

        str1 = "加密过程：\n" + "加密用时：" + f'{temp:.15f}' + "\n"
        str1 += "签名(r,s)为：(" + str(r) + ',' + str(s) + ')'
        self.textBrowser.setText(str1)#在输出框显示相应信息
        return

    def decode(self):  # 点击 decode 触发
        t = time.time()
        # 获取输入框的m、r和s
        msg = self.lineEdit.text()
        m = number.bytes_to_long(msg.encode('utf-8'))
        r = int(self.lineEdit_2.text())
        s = int(self.lineEdit_3.text())
        v = decode(m, r, s, self.p, self.q, self.g, self.y)# 验证签名
        temp = time.time()-t

        str2 = "解密过程：\n" + "解密用时："+ f'{temp:.15f}' + "\n"
        str2 += "r值为:"+str(r) + "\n"
        str2 += "v值为:"+str(v) + "\n"
        if (r == v):
            str2 += "r与v相同，数字签名鉴定通过鉴别"
        else:
            str2 += "鉴定失败"
        self.textBrowser.clear()#清空输出框
        self.textBrowser.setText(str2)#在输出框显示相应信息
        return

if __name__ == '__main__':
    app = QApplication(sys.argv)  # 在 QApplication 方法中使用，创建应用程序对象
    myWin = MyMainWindow()  # 实例化 MyMainWindow 类，创建主窗口
    myWin.show()  # 在桌面显示控件 myWin
    sys.exit(app.exec_())  # 结束进程，退出程序
