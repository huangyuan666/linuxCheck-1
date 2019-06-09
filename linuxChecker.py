# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     linuxChecker
   Description :
   Author :       CoolCat
   date：          2019/4/2
-------------------------------------------------
   Change Activity:
                   2019/4/2:
-------------------------------------------------
"""
__author__ = 'CoolCat'


import os
import time
import sys
import requests

# def log(ip,status):
#     import sys
#
#     class Logger(object):
#         def __init__(self, filename="run.log"):
#             self.terminal = sys.stdout
#             self.log = open(filename, "a")
#
#         def write(self, message):
#             self.terminal.write(message)
#             self.log.write(message)
#
#         def flush(self):
#             pass
#
#     if status == "0":
#         if os.path.exists(str(ip) + '.log'):
#             os.remove(str(ip) + '.log')
#         sys.stdout = Logger(str(ip) + '.log')
#     elif status == "1":
#         exit(sys.stdout)
#         f = open("loginError.log", "a")
#         f.write(ip + ' 登录失败\n')
#         f.close()
#         pass




#cat /etc/passwd |cut -f 1 -d :
def login(ip, port, user, pwd):
    ssh = paramiko.SSHClient()
    key = paramiko.AutoAddPolicy()
    ssh.set_missing_host_key_policy(key)
    ssh.connect(ip, port, user, pwd, timeout=10)
    #超时设置为10秒是为了后面find命令的执行。
    return ssh

def command(ssh, cmd):
    print("当前执行的命令为：" + cmd + "\n")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    return stdout.readlines()

def getSysVersion(ssh):
    print("#" * 100)

    results = command(ssh, "uname -nao")
    for result in results:
        sysVer = str(result).replace("\r", "").replace("\n", "")
        print("系统版本为：{}\n".format(sysVer))



def userCheck(ssh):

    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在进行口令策略检测")

    results = command(ssh, "cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk \'{print $2}\'")
    for result in results:
        dayMax = str(result).replace("\r", "").replace("\n", "")
        print("口令生存周期为{}天".format(dayMax))
        if int(dayMax) >= 90:
            print("口令的生存期长于90天,不符合要求。")
        else:
            print("口令的生存期不长于90天,符合要求。")

    results = command(ssh, "cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk \'{print $2}\'")
    if len(results) == 0 :
        print("未设定用户密码最小长度限制,不符合要求。")
    else:
        for result in results:
            passmin = str(result).replace("\r", "").replace("\n", "")
            print("用户密码最小长度为{}位".format(passmin))
            if int(passmin) >= 8:
                print("用户密码最小长度大于等于8,符合要求")
            else:
                print("用户密码最小长度小于8,不符合要求")


def howManyUsers(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检查可登录的账号数量")
    results = command(ssh, "cat /etc/shadow")
    n = 0
    users = []
    for result in results:
        user  = str(result).replace("\r", "").replace("\n", "")
        if "*"  not in user:
            if "!" not in user:
                n += 1
                users.append(user)
    print("存在{}个可登录的用户,分别为:".format(n))
    for user in users:
        print(user.split(":")[0])
    if n == 1:
        print("仅有一个可登录的账户,不符合要求\n")
    else:
        print("可登录的账户不止一个,符合要求\n")

def checkRoot(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检查root权限组中的用户数量")
    results = command(ssh, "cat /etc/group")
    n = 0
    roots = []
    for result in results:
        user  = str(result).replace("\r", "").replace("\n", "")
        # print(user.split(":")[-2])
        if user.split(":")[-2] == "0":
            roots.append(user.split(":")[0])
            n += 1

    print("ROOT用户组存在{}个账户,分别为:".format(n))

    for root in roots:
        print(root)


    # print(roots)
    # print("存在{}个可登录的用户,分别为:".format(n))
    # for user in roots:
    #     gourp = user.split(":")[0]

    if n == 1:
        print("仅有一个root权限的账户,符合要求\n")

    else:
        print("不仅一个root权限的账户,不符合要求\n")


def suCheak(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测是否禁止任何人使用su提升权限为root")
    sus = []
    results = command(ssh, "cat /etc/pam.d/su")
    for result in results:
        su = str(result).replace("\r", "").replace("\n", "")
        print(su)
        sus.append(su)

    if "auth sufficient /lib/security/pam_rootok.so" in sus:
        print("已禁止任意用户使用su提升权限为root\n")
    elif "auth required /lib/security/pam" in sus:
        print("可使用su提升权限为root的账户有{}\n".format(su.split("=")[-1]))
    else:
        print("未禁止任意用户使用su提升权限为root,不符合要求。\n")


def fileCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测敏感文件权限情况...")

    results = command(ssh, "ls -l /etc/*")
    for result in results:
        fileCheck = str(result).replace("\r", "").replace("\n", "")
        print(fileCheck)
    print("\n")
        # print("/etc/passwd 的权限为：{}".format(passwdCheck.split(" ")[0]))
        # if passwdCheck.split(" ")[0] == "-rw-r--r--":
        #     print("所有用户都应可读，符合要求。")
        # else:
        #     print("/etc/passwd文件权限非所有用户都应可读，不符合要求。")



def umaskCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测umask参数的值...")
    results = command(ssh, "cat /etc/login.defs")
    for result in results:
        umask = str(result).replace("\r", "").replace("\n", "")
        if "UMASK" in umask and "#" not in umask:
            print(umask)
            print("当前用户创建的文件权限默认为{}\n".format(str(777 -int(umask.split("\t")[-1]))))

# def ftpCheck(ssh):
#     print(time.strftime('[%H:%M:%S]:') + "正在检测ftp相关值...")
#     results = command(ssh, "ps -ef | grep ftp")
#     ftpStatus = []
#     for result in results:
#         ftp = str(result).replace("\r", "").replace("\n", "")
#         if "grep" not in ftp:
#             ftpStatus.append(ftp)
#
#     if len(ftpStatus) == 0:
#         print("ftp未开启")
#     else:
#         print()


def logCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测log功能启用情况...")
    results = command(ssh, "ps -ef | grep rsyslog")
    n = 0
    m = 0
    for result in results:
        log = str(result).replace("\r", "").replace("\n", "")
        print(log)
        if ("/usr/sbin/rsyslogd" in log):
            n = 1
        elif ("/sbin/rsyslogd" in log):
            n = 1
        elif("/usr/sbin/rsyslogd" in log):
            n = 1
        else:
            pass

    if n == 1:
        print("rsyslog已启用\n")
    else:
        print("rsyslog未启用\n")

    results = command(ssh, "ps -ef | grep syslog")

    n = 0
    for result in results:
        log = str(result).replace("\r", "").replace("\n", "")
        print(log)
        if ("/usr/sbin/syslog" in log):
            n = 1
        elif ("/sbin/syslog" in log):
            n = 1
        elif("/usr/sbin/syslog" in log):
            n = 1
        else:
            pass

    if n == 1:
        print("syslog已启用\n")
        m = 1
    else:
        print("syslog未启用\n")



    # results = command(ssh, "ps -ef | grep syslog")
    # logs = []
    # for result in results:
    #     log = str(result).replace("\r", "").replace("\n", "")
    #     print(log)
    #     logs.append(log)
    # if "/usr/sbin/syslog" in logs[1] or "/sbin/syslog" in logs[0] or "/usr/sbin/syslog" in logs[1]:
    #     print("syslog已启用")
    #     n = 1
    # else:
    #     print("syslog未启用")


    if m == 1:
        print("日志功能符合要求\n")
    else:
        print("日志功能不符合要求\n")

def sshRemote(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测是否禁用了ssh远程登录...")
    results = command(ssh, "cat /etc/ssh/sshd_config | grep PermitRootLogin | grep -v ^# | awk '{print $2}'")
    for result in results:
        PermitRootLogin = str(result).replace("\r", "").replace("\n", "")
        if PermitRootLogin == 'yes':
            print("PermitRootLogin默认的值为yes 未禁用ssh远程登录 不符合要求\n")
        else:
            print("PermitRootLogin默认的值为no 禁用ssh远程登录 符合要求\n")



def telnetCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测是否关闭了telnet服务...")
    results = command(ssh, "ps -ef |grep telnet")
    for result in results:
        telnet = str(result).replace("\r", "").replace("\n", "")
        print(telnet)
        if "grep" in telnet:
            print("telnet未开启 符合要求\n")
        else:
            print("telnet服务开启 不符合要求\n")

def unNeed(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测不必要的服务...")
    results = command(ssh, "ps -ef")
    for result in results:
        psUnNeed = str(result).replace("\r", "").replace("\n", "")
        print(psUnNeed)

    results = command(ssh, "chkconfig --list")
    for result in results:
        chkUnNeed = str(result).replace("\r", "").replace("\n", "")
        print(chkUnNeed)

    results = command(ssh, "cat /etc/xinetd.conf")
    for result in results:
        xinetdUnNeed = str(result).replace("\r", "").replace("\n", "")
        print(xinetdUnNeed)

def bannerCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在检测Banner信息...")
    results = command(ssh, "cat /etc/issue")
    for result in results:
        banner1 = str(result).replace("\r", "").replace("\n", "")
        print(banner1)


    results = command(ssh, "cat /etc/issue.net")
    for result in results:
        banner2 = str(result).replace("\r", "").replace("\n", "")
        print(banner2)

    results = command(ssh, "cat /etc/motd")
    for result in results:
        banner3 = str(result).replace("\r", "").replace("\n", "")
        print(banner3)

    results = command(ssh, "cat /etc/rc.d/rc.local")
    for result in results:
        banner4 = str(result).replace("\r", "").replace("\n", "")
        print(banner4)

def findSensitiveFile(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在寻找存在的敏感文件...")
    results = command(ssh, "find / -name .netrc")
    for result in results:
        fsf1 = str(result).replace("\r", "").replace("\n", "")
        print(fsf1)

    results = command(ssh, "find / -name .rhosts")
    for result in results:
        fsf2 = str(result).replace("\r", "").replace("\n", "")
        print(fsf2)

    results = command(ssh, "find / -name hosts.equiv")
    for result in results:
        fsf3 = str(result).replace("\r", "").replace("\n", "")
        print(fsf3)

def loginFailDel(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在查看登录失败处理策略...")
    results = command(ssh, "cat /etc/pam.d/login")
    for result in results:
        loginFail1 = str(result).replace("\r", "").replace("\n", "")
        print(loginFail1)

    results = command(ssh, "cat /etc/pam.d/password-auth")
    for result in results:
        loginFail2 = str(result).replace("\r", "").replace("\n", "")
        print(loginFail2)

def iptablesCheck(ssh):
    print("#" * 100)
    print(time.strftime('[%H:%M:%S]:') + "正在查看iptables策略...")

    results = command(ssh, "echo `firewall-cmd --state` | base64")
    n = 0
    for result in results:
        state = str(result).replace("\r", "").replace("\n", "")
        if state == "Cg==":
            n = 1
    if n == 1 :
        print("not running")
    else:
        print("firewall running")

        print(state)

    results = command(ssh, "iptables -L -n")
    for result in results:
        iptables = str(result).replace("\r", "").replace("\n", "")
        print(iptables)

def ssha(host):
    ip = host.replace("\r", "").replace("\n", "").split("/")[0]
    user = host.replace("\r", "").replace("\n", "").split("/")[1]
    pwd = host.replace("\r", "").replace("\n", "").split("/")[2]

    # ip = host.replace("\r", "").replace("\n", "").split("	")[0]
    # user = host.replace("\r", "").replace("\n", "").split("	")[-1].split("/")[0]
    # pwd = host.replace("\r", "").replace("\n", "").split("	")[-1].split("/")[-1]
    # log(ip)

    try:

        sshd = login(ip, port, user, pwd)
        print(time.strftime('\n[%H:%M:%S]') + str(ip) + "登录成功")

        print(time.strftime('[%H:%M:%S]正在检查') + str(ip) + "请稍等...")

        if os.path.exists(str(ip) + ".log"):
            os.remove(str(ip) + ".log")

        logs = sys.stdout
        with open(str(ip) + ".log", "a") as f:
            sys.stdout = f

            print(time.strftime(
                '\n============================================Created at %H:%M:%S============================================'))
            print(time.strftime('[%H:%M:%S]') + str(ip) + "登录成功\n")

            getSysVersion(sshd)

            howManyUsers(sshd)

            userCheck(sshd)

            checkRoot(sshd)

            suCheak(sshd)

            fileCheck(sshd)

            try:
                umaskCheck(sshd)
            except:
                pass
            try:
                logCheck(sshd)
            except:
                pass
            sshRemote(sshd)
            telnetCheck(sshd)

            unNeed(sshd)

            bannerCheck(sshd)

            findSensitiveFile(sshd)

            loginFailDel(sshd)

            iptablesCheck(sshd)

            print(time.strftime(
                '\n============================================Finished at %H:%M:%S============================================'))

            sys.stdout = logs
            print(time.strftime('[%H:%M:%S]') + str(ip) + "检查完成\n")
            f.close()

        # iptablesCheck(sshd)
        # logCheck(sshd)

    except Exception as e:
        print(time.strftime('[%H:%M:%S]') + str(ip) + "登录失败")
        f = open("loginError.log", "a")
        f.write(ip + ' 登录失败\n')
        f.close()
        print(e)
        pass


if __name__ == '__main__':

    print("+"*50)
    print(time.strftime('[%H:%M:%S]:') + "请输入单个txt文本或者单条ip,如：")
    print(time.strftime('[%H:%M:%S]') + "host.txt或者127.0.0.1/root/root")
    print("+" * 50)

    hosts = input("Hosts:")

    try:
        import paramiko
    except:
        os.system("pip install paramiko")
        print(time.strftime('[%H:%M:%S]:') + "如果脚本报错请重装cryptography模块为2.4.2版本")
        pass

    # ssha(hosts)

    port = '22'

    if "txt" in hosts:
        for host in open(hosts):
            ssha(host)
    else:
        ssha(hosts)


















