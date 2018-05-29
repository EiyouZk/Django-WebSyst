#!/usr/bin/python
#-*-coding:utf-8 -*-

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.http import require_POST
from .forms import LoginForm, UserRegistrationForm, UserEditForm, ProfileEditForm, ChangeForm
from .models import Profile, Contact, ServerTable, ServerGroup, ServerStatus, ServerNotice,ActionLog,UserRule,ImportProcess,WhiteList,SuperList,InterceptIP,AppControl,AccoutProt,OutsideDevice,PortSecurity,ServerGateway,NetFirewall,UrlWhiteList,Strategy,PortIpSegment
from common.decorators import ajax_required
# from actioactionsns.moactionsdels import Action
# from actions.utils import create_action
from django.views.decorators.cache import cache_page
import logging
import json
from django.core.mail import EmailMultiAlternatives
import os,sys,shutil
import time,datetime
# from django.utils import timezone as datetime

import makebag
# import win32process,win32event
# from dwebsocket.decorators import accept_websocket,require_websocket

import base64
from django.contrib.staticfiles.templatetags.staticfiles import static
# from django.shortcuts import render_to_response
# from django.template import RequestContext

from aes import prpcrypt
import MySQLdb,math
import urllib, urllib2
from zipfile import ZipFile
from os import listdir
from os.path import isfile,isdir,join
import random
from io import BytesIO
from drawpic import create_validate_code

from websocket import create_connection
# from ws4py.client.threadedclient import WebSocketClient
import subprocess
from threading import Thread
from time import sleep
import linecache
from shell import Shell


reload(sys);
sys.setdefaultencoding("utf8")

faillogin = {}

# 用户登录
def user_login(request):
    logging.debug('login')
    # (pub_key, priv_key) = rsa.newkeys(256)  ## 生成公钥私钥
    # pubkey_e = hex(pub_key.e)
    # pubkey_n = hex(pub_key.n)
    # request.session['privkey'] = priv_key
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            cd = form.cleaned_data
            logging.debug(type(cd))
            logging.debug(type(cd))
            passwd = cd['password']
            de_pass = base64.b64decode(passwd)
            code = request.POST.get('check_code')
            if code.upper() != request.session['CheckCode'].upper():
                return render(request, 'account/login.html',{'form': form, 'error':'error_code'})

            user = authenticate(username=cd['username'], password=de_pass)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return render(request, 'account/index.html')
                    # return HttpResponse('Authenticated successfully')
                else:
                    return render(request, 'account/login.html', {'form': form , 'error':'error'})
            else:
                user = cd['username']
                failtime = faillogin.get(user)
                if failtime:
                    faillogin[user] = failtime +1
                else:
                    faillogin[user] = 1

                lastlogin = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                return render(request, 'account/login.html', {'form': form, 'error':'error'})
    else:
        form = LoginForm()
    return render(request, 'account/login.html', {'form':form,'section':'login'})

# 图片验证码
def check_code(request):
    logging.debug('check_code')
    print 'check_code'
    stream = BytesIO()  # 开辟一块内存空间，不用写在外存，减少读写操作
    img, code = create_validate_code()
    img.save(stream, 'PNG')
    request.session['CheckCode'] = code
    return HttpResponse(stream.getvalue())

# 生成测试数据
def maketestdata(request):
    obj = request.GET['obj']
    if 'make' == obj:
        for i in range(1,100):
            servername = 'test_%d' % (i)
            ServerTable.objects.create(servername=servername, servergroup='Un_Group', user=request.user, serverip='192.168.1.1',
                                       logincity='cq')
    elif 'del' == obj:
        ServerTable.objects.filter(user=request.user, servername__contains='test_').delete()
    return HttpResponse('success')

# 注册
def register(request):
    passlen = 6
    bshortpass = False
    isemailexist = False
    if request.method == 'POST':
        user_form = UserRegistrationForm(request.POST)
        formdata= user_form.data
        password = formdata['password']
        user = formdata['username']
        passlen = len(password)
        verify_email = formdata['email']

        profile = Profile.objects.filter(verify_email = verify_email)
        if profile:
            isemailexist = True
        elif passlen>=6 and user_form.is_valid():
            # Create a new user object but avoid saving it yet
            new_user = user_form.save(commit=False)
            # Set the chosen password
            new_user.set_password(user_form.cleaned_data['password'])
            # Save the User object
            new_user.save()
            # Create the user profile
            pc = prpcrypt("qazwsxedcrfvtgbh")
            msg = user.encode("utf-8")
            encryptedID = pc.encrypt(msg)
            Profile.objects.create(user=new_user,verify_email = verify_email,profileID=encryptedID)
            # create_action(new_user, 'has created an account')
            return render(request,'account/register_done.html',{'new_user':new_user})
    else:
        user_form = UserRegistrationForm()
    errors = user_form.errors
    ret = '{'
    username_err = ''
    password_err = ''
    password2_err = ''
    email_err = ''
    for (d,x) in errors.items():
        if 'username' == d:
            username_err = x
        if 'email' == d:
            email_err = x
        if 'password' == d:
            password_err = x
        if 'password2' == d:
            password2_err = x

    if passlen < 6:
        bshortpass = True
    return render(request, 'account/register.html', {'user_form':user_form,'username_err':username_err,'email_err':email_err,'password_err':password_err,'password2_err':password2_err,'isemailexist':isemailexist,'isshortpass':bshortpass})


# 修改密码
@login_required
def passwordchange(request):
    if request.method == 'POST':
        username = request.user
        u = User.objects.get(username__exact=username)
        oldpass = request.POST.get('old_password')
        newpass = request.POST.get('new_password1')
        try:
            user = authenticate(username=username, password=oldpass)
            if user is not None:
                if user.is_active:
                    u.set_password(newpass)
                    u.save()
                    logout(request)
                    return render(request, 'account/login.html',{"error":"changepass"})
            return render(request, 'account/password_change_form.html', {"ret": 'fail'})
        except:
            return render(request, 'account/password_change_form.html', {"ret": 'fail'})
    return render(request, 'account/password_change_form.html',{"ret":''})

# 生成配置文件
def makeconfile(user):
    try:
        BASE_DIR = os.path.dirname(os.path.dirname(__file__))
        static_path = os.path.join(BASE_DIR, 'collected_static')
        # Windows
        # config_path = static_path + "\\nsis\\Radar\\login.ini"
        # bat_path = static_path + "\\nsis\\Radar\\makesetup.bat"
        # pakage_path = static_path + "\\nsis\\Radar\\Setup.exe"
        # newpakage_path = static_path + "\\nsis\\" + 'Radar_%s.exe' % (user)

        #Linux
        config_path = static_path + "//nsis//Radar//login.ini"
        sh_path = static_path + "//nsis//Radar//makesetup.sh"

        # if 'setup' == type:
        pakage_path = static_path + "//nsis//Radar//Setup.exe"
        newpakage_path = static_path + "//nsis//" + 'Radar_%s.exe' % (user)
        # elif 'update' == type:
        #     pakage_path = static_path + "//nsis//Radar//Setup_Update.exe"
        #     newpakage_path = static_path + "//nsis//" + 'Radar_Update_%s.exe' % (user)

        if os.path.exists(config_path):
             os.remove(config_path)

        # os.mknod(config_path)
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = user.encode("utf-8")
        encryptedmsg = pc.encrypt(msg)

        config_file = open(config_path,'w')
        user_info = '[config]\r\nip=192.168.60.70\r\nport=8099\r\nid=%s' % (encryptedmsg)
        config_file.write(user_info)
        config_file.close()

        # Windows
        # p = subprocess.Popen("cmd.exe /c" + bat_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # curline = p.stdout.readline()
        # while (curline != b''):
        #     print(curline)
        #     curline = p.stdout.readline()
        # p.wait()

        #Linux
        # os.system(bat_path)
        # if 'setup' == type:
        data = os.popen('/home/zouke/LeiDunSys/collected_static/nsis/Radar/makesetup.sh')
            # keeprunning = Shell("/home/zouke/LeiDunSys/collected_static/nsis/Radar/makesetup.sh")
            # keeprunning.run_background()
        print data.read()
        # elif 'update' == type:
        #     # data = os.popen('/home/zouke/LeiDunSys/collected_static/nsis/Radar/makeupdate.sh')
        #     keeprunning = Shell('/home/zouke/LeiDunSys/collected_static/nsis/Radar/makeupdate.sh')
        #     keeprunning.run_background()
            # executeSh("/home/zouke/LeiDunSys/collected_static/nsis/Radar/makeupdate.sh",None,5000,True)
            # data = os.popen('/home/zouke/LeiDunSys/collected_static/nsis/Radar/makeupdate.sh')
        # p = subprocess.Popen('/home/zouke/LeiDunSys/collected_static/nsis/Radar/makesetup.sh', stdout=subprocess.PIPE, shell = True, stderr=subprocess.STDOUT)
        # curline = p.stdout.readline()
        # while (curline != b''):
        #     print(curline)
        #     curline = p.stdout.readline()
        # p.wait()

        if os.path.exists(pakage_path):
            shutil.move(pakage_path, newpakage_path)
    except Exception as e:
        print('something error')
        print e
    finally:
        config_file.close()

def executeSh(cmdstring,cwd=None,timeout=None,shell=False):
    if shell:
        cmdstring_list = cmdstring
    else:
        cmdstring_list = shlex.split(cmdstring)
    if timeout:
        end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
    sub = subprocess.Popen(cmdstring_list, cwd=cwd, stdin=subprocess.PIPE, shell=shell, bufsize=4096)

    while sub.poll() is None:
        time.sleep(0.1)
        if timeout:
            if end_time <= datetime.datetime.now():
                raise Exception("Timeout：%s" % cmdstring)

    return str(sub.returncode)

# 获取最新的版本号
def postversion(request):
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    nsi_path = os.path.join(BASE_DIR, 'collected_static') + '/nsis/Radar/RadarSetup.nsi'
    version = linecache.getlines(nsi_path)[4]
    ver = version[25:-2]
    return HttpResponse(ver)

# 获取最新版本的客户端更新包
def makeclientupdate(request):
    if request.body:
        req = json.loads(request.body)
        id = req['Id']
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']
    else:
        id = '255608981359f1d3106aec437e224c56'
        ip = '192.168.60.41'

    try:
        profile = Profile.objects.get(profileID=id)
        if not profile:
            logging.debug('Disabled account b')
            return HttpResponse('{errcode:2}')

        # server = ServerTable.objects.get(user = profile.user, serverip=ip)
        # makeconfile(server.user, 'update')
        # Radar_Update.exe固定的更新包名字，由运维人员上传
        url = 'http://192.168.60.70:8099/static/nsis/Radar_rrer.exe'
        return HttpResponse(url)
    except:
        return HttpResponse('fail')

# 保存客户端的优化扫描信息
def serveroptimize(request):
    serverid = request.GET['serverid']
    obj = request.GET['obj']
    type = request.GET['type']

    server = ServerTable.objects.get(id=serverid)
    msg = '{"method": "ServerOptimize","obj":"%s","type":%d}' % (obj,int(type))
    pc = prpcrypt("qazwsxedcrfvtgbh")
    msg = msg.encode("utf-8")
    encryptedmsg = pc.encrypt(msg)
    if SendToClient(server.serverip, encryptedmsg, True):
        return HttpResponse('success')
    else:
        return HttpResponse('fail')

# 保存客户端传上来的优化项
def saveoptimize(request):
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        obj = req['obj']
        result = req['result']
        server = ServerTable.objects.get(serverip=ip)

        if 'registry' == obj:
            server.result_registry = result
            server.update_registry = True
        elif 'service' == obj:
            server.result_service = result
            server.update_service = True
        elif 'account' == obj:
            server.result_account = result
            server.update_account = True
        server.save()

        return HttpResponse('success')

# 获取扫描结果
def getresult(request):
    serverid = request.GET.get('serverid')
    obj = request.GET.get('obj')
    server = ServerTable.objects.get(id=serverid)

    msg = '获取扫描结果失败'
    if 'registry' == obj:
        if server.update_registry:
            msg = server.result_registry
    elif 'service' == obj:
        if server.update_service:
            msg = server.result_service
    elif 'account' == obj:
        if server.update_account:
            msg = server.result_account

    return HttpResponse(msg)

    # Linux环境下生成客户端
def makeclientlinux(request):
    try:
        user = request.GET.get('user')
        if not user:
            user = "test"
        print 'makeclientlinux'
        makeconfile(user)
        return HttpResponse('success')
    except:
        return HttpResponse('fail')

# 编辑个人信息
@login_required
def edit(request):
    if request.method == 'POST':
        user_form = UserEditForm(instance=request.user,
                                 data=request.POST)
        profile_form = ProfileEditForm(instance=request.user.profile,
                                       data=request.POST,
                                       files=request.FILES)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            # messages.success(request, 'Profile updated successfully')
        # else:
            # messages.error(request, 'Error updating your profile')
    else:
        user_form = UserEditForm(instance=request.user)
        profile_form = ProfileEditForm(instance=request.user.profile)
    return render(request, 'account/edit.html', {'user_form':user_form,
                                                 'profile_form':profile_form})

# 输入网站地址进入首页
def index(request) :
    return render(request, 'account/index.html')
  
@login_required
# @cache_page(60*15)
def cloudset(request):
    logging.debug(request.user)
    serverinfo = ServerTable.objects.filter(user=request.user)
    netcount_server = []
    netcount_flow = []
    initnetUpcount = ''
    initnetDowncount = ''
    for server in serverinfo:
        netcount_server.append(server.servername)
        netcount_flow.append(server.networkUpFlow)
        initnetUpcount = serverinfo[0].networkUpFlow
        initnetDowncount = serverinfo[0].networkDownFlow

    statusarry = []
    Invadserver = []
    statuss = ServerStatus.objects.all()
    for status in statuss:
        logging.debug(status.statuscode)
        servers = ServerTable.objects.filter(user=request.user,serverstatus=status.statuscode)
        statusarry.append(len(servers))
        if status.statuscode == 'Invade':
            Invadserver = ServerTable.objects.filter(user=request.user,serverstatus=status.statuscode)


    logging.debug(statusarry)

    return render(request, 'account/dashboard.html',{'section': 'cloudset', 'serverinfo': serverinfo, 'netcount_server': netcount_server,'netcount_flow': netcount_flow, 'Invade': statusarry[0], 'H_Risk': statusarry[1],'Unusual': statusarry[2], 'Normal': statusarry[3], 'Invadserver': Invadserver,'initnetUpcount':initnetUpcount,'initnetDowncount':initnetDowncount})

    # return render(request, 'account/dashboard.html', {'section':'cloudset','serverinfo':serverinfo,'netcount_server':netcount_server,'netcount_flow':netcount_flow,'Invade':statusarry[0],'H_Risk':statusarry[1],'Unusual':statusarry[2],'Normal':statusarry[3],'Invadserver':Invadserver})
    
def user_list(request):
    users = User.objects.filter(is_active=True)
    return render(request, 'account/user/list.html', {'section':'dashboard',
                                                      'users':users})

# @accept_websocket
# def echo(request):
#     if not request.is_websocket():#判断是不是websocket连接
#         try:#如果是普通的http方法
#             message = request.GET['message']
#             return HttpResponse(message)
#         except:
#             return render(request,'cloundset/notification.html')
#     else:
#         for message in request.websocket:
#             request.websocket.send('success')#发送消息到客户端

# 客户端卸载功能
def clientuninstall(request):
    if request.method == 'GET':
        ip = GetRequestIP(request)
        server = ServerTable.objects.filter(serverip=ip)
        if server:
            NetFirewall.objects.filter(servername=server[0].servername).delete()
            UserRule.objects.filter(servername=server[0].servername).delete()
            ImportProcess.objects.filter(servername=server[0].servername).delete()
            ServerTable.objects.filter(serverip=ip).delete()
        return render(request, 'account/clientuninstall.html',{'section':'uninstall'})
    else:
        return render(request, 'account/clientuninstall.html')

  # 根据IP获取登录城市
def GetLoginCityByIP(ip):
    try:
        urlfp = urllib.urlopen('http://ip.taobao.com/service/getIpInfo.php?ip=' + ip)
        ipdata = urlfp.read()
        urlfp.close()

        allinfo = json.loads(ipdata)
        for oneinfo in allinfo:
            if "code" == oneinfo:
                if 0 == allinfo[oneinfo]:
                    print "ip -: " + allinfo["data"]["ip"]
                    print "city -: " + allinfo["data"]["country"],
                    print allinfo["data"]["region"],
                    print allinfo["data"]["city"],
                    print "(" + allinfo["data"]["isp"] + ")"
                    return allinfo["data"]["city"]
                else:
                    print "parse error"
                    return ''
    except Exception, e:
        logging.debug(e)

# 接收客户端上传的服务器运行状态信息
def postserverinfo(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        try:
            param = req['param']
            status = param['status']

            ServerTable.objects.filter(serverip=ip).update(serverstatus=status)
            return HttpResponse('success')
        except:
            return HttpResponse('fail')


# 客户端登录
def clientlogin(request):
    logging.debug('clientlogin')
    req = json.loads(request.body)
    servername = req['HostName']
    installdate = req['InistallTime']

    if not installdate:
        installdate = time.strftime('%Y-%m-%d',time.localtime(time.time()))

    # user='liuluok123'
    # pc = prpcrypt("qazwsxedcrfvtgbh")
    # msg = user.encode("utf-8")
    # encryptedID = pc.encrypt(msg)

    id = req['Id']
    profile = Profile.objects.get(profileID=id)
    if not profile:
        print ('Disabled account b')
        return HttpResponse('{errcode:2}')

    user = profile.user
               
    ip= GetRequestIP(request)
    if ip == '127.0.0.1':
        ip = req['ip']

    # 获取客户端所在IP
    city = GetLoginCityByIP(ip)
    # server = ServerTable.objects.filter(servername = servername)
    # if not server:
    #     # 同一台服务器，换了IP之后重新登录，HostName名字一样的,删除旧的IP登录的服务器
    #     if server[0].ip != ip:
    #         NetFirewall.objects.filter(user=server.user, servername=server.servername).delete()
    #         UserRule.objects.filter(user=server.user, servername=server.servername).delete()
    #         ImportProcess.objects.filter(user=server.user, servername=server.servername).delete()
    #         PortSecurity.objects.filter(user=server.user, servername=server.servername).delete()
    #         PortIpSegment.objects.filter(user=server.user, servername=server.servername).delete()
    #         SuperList.objects.filter(user=server.user, servername=server.servername).delete()
    #         OutsideDevice.objects.filter(user=server.user, servername=server.servername).delete()
    #         ServerTable.objects.filter(id=selected).delete()

    server = ServerTable.objects.filter(serverip = ip)
    # 全新的服务器Ip在数据库中没有记录
    if not server:
        ServerTable.objects.create(servername=servername,servergroup='Un_Group', user=profile.user,serverip=ip,logincity=city,protected_days=installdate,lastlogin=time.strftime('%Y-%m-%d',time.localtime(time.time())))
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,rulename='禁止系统目录创建DLL文件', rulepath='C:/Windows',rulestatus=True,forbidaction='check_no_create;', fileprottype=3, refuseExts='C:/Windows')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止系统目录创建EXE文件', rulepath='C:/Windows',
                                rulestatus=True,forbidaction='check_no_create;', fileprottype=3, refuseExts='exe')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止目录创建DLL文件', rulepath='C:/Windows/system32', rulestatus=True,
                                forbidaction='check_no_create;', fileprottype=3, refuseExts='dll')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止目录创建EXE文件', rulepath='C:/Windows/system32', rulestatus=True,
                                forbidaction='check_no_create;', fileprottype=3, refuseExts='exe')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止执行SC命令', rulepath='C:/Windows/system32', rulestatus=True,
                                forbidaction='check_no_run;', fileprottype=3, refuseFiles='sc')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止劫持HOSTS文件', rulepath='C:/Windows/system32/drivers/etc', rulestatus=True,
                                forbidaction='check_no_write;', fileprottype=3, refuseFiles='hosts')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止sethc.exe和utilman.exe执行', rulepath='C:/Windows/system32', rulestatus=True,
                                forbidaction='check_no_run;', fileprottype=3, refuseFiles='sethc.exe|utilman.exe')
        UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
                                rulename='禁止net命令执行', rulepath='C:/Windows/system32', rulestatus=True,
                                forbidaction='check_no_run;', fileprottype=0, refuseFiles='net|net1')
        # UserRule.objects.create(servername=servername, featuremodule='file_prot_sys', user=user,
        #                         rulename='禁止修改Radar目录', rulepath='C:/Program Files/Radar', rulestatus=True,
        #                         forbidaction='check_no_run;check_no_del;check_no_write;check_no_create;check_no_rea;',
        #                         fileprottype=3, allowProcess='Radar.exe')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,
                                rulename='禁止添加或修改自动运行程序1', rulepath='HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/Run', rulestatus=True,
                                forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,
                                rulename='禁止添加或修改自动运行程序2', rulepath='HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True,
                                forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='net|net1')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,
                                rulename='禁止添加或修改自动运行程序1(x86)', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run', rulestatus=True,
                                forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,
                                rulename='禁止添加或修改自动运行程序2(x86)', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True,
                                forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,rulename='禁止添加或修改自动运行程序1(x64)', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Run', rulestatus=True,forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
        UserRule.objects.create(servername=servername, featuremodule='registry_prot_sys', user=user,rulename='禁止添加或修改自动运行程序2(x64)', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True,forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
        NetFirewall.objects.create(user=user, servername=servername)
    else:
        lastlogin = time.strftime('%Y-%m-%d',time.localtime(time.time()))
        ServerTable.objects.filter(serverip=ip).update(lastlogin = lastlogin,logincity=city)

    userinfo = '{"errcode":0,"username":"%s"}' % (profile.user)
    print userinfo
    return HttpResponse(userinfo)

# 获取年月日
def getYearMonthDate(t):
    timearray = t.split('-')
    year = timearray[0]
    month = timearray[1]
    date = timearray[2]
    return datetime.date(int(year),int(month),int(date))

def shoppage(request):
    users = User.objects.filter(is_active=True)
    return render(request, 'account/shoppage.html', {'users':users})

def service(request):
    return render(request, 'account/service.html')    
 
@login_required
def setting(request):
    if request.method=="POST":   
        alarmWays = request.POST.getlist("alarmWays")       
        profiles = Profile.objects.filter(user=request.user)
                
        for profile in profiles:
            savesetting(profile,alarmWays)
            
            
    profiles = Profile.objects.filter(user=request.user)
    return render(request, 'cloundset/setting.html', {'section':'setting','profiles':profiles})
    
@login_required
def strategy(request):
    serverinfo = ServerTable.objects.filter(user=request.user)
    strategies = Strategy.objects.filter(user=request.user,type='Windows')
    servernum = serverinfo.count()
    for strategy in strategies:
        servers = ServerTable.objects.filter(user=request.user,strategyname= strategy.strategyname)
        strategy.count = servers.count()
        strategy.save()

    return render(request, 'cloundset/strategy.html', {'section':'strategy','serverinfo':serverinfo,'servernum':servernum,'strategies':strategies})

@login_required
def strategytemp(request):
    strategyid = request.GET.get('strategyid')
    strategy = Strategy.objects.get(id=strategyid)
    
    return render(request, 'cloundset/strategytemp.html', {'section':'strategy','strategy':strategy})
    
# linux安全策略模版
@login_required
def strategylinux(request):
    serverinfo = ServerTable.objects.filter(user=request.user)
    strategies = Strategy.objects.filter(user=request.user,type='Linux')
    servernum = serverinfo.count()
    for strategy in strategies:
        servers = ServerTable.objects.filter(user=request.user,strategyname= strategy.strategyname)
        strategy.count = servers.count()
        strategy.save()
        
    return render(request, 'cloundset/strategylinux.html', {'section':'strategy','serverinfo':serverinfo,'servernum':servernum,'strategies':strategies})

@login_required
def securityset(request):
    serverinfo = ServerTable.objects.filter(user=request.user)
    return render(request, 'cloundset/securityset.html', {'section':'securityset','serverinfo':serverinfo})

# 服务器管理页面    
@login_required
def servermanage(request):
    logging.debug('servermanage_debug')
    serverinfo = ServerTable.objects.filter(user=request.user)
    servergroups = ServerGroup.objects.filter(user=request.user)

    searchname = ''
    if request.method=="POST": 
        logging.debug(request.POST)
        logging.debug('servermanage_debugb')
        searchname = request.POST.get("searchname")

        selecteds = request.POST.getlist("selectdel")
        for selected in selecteds:
            logging.debug(selected)
            server = ServerTable.objects.get(id=selected)
            NetFirewall.objects.filter(user=server.user, servername=server.servername).delete()
            UserRule.objects.filter(user=server.user, servername=server.servername).delete()
            ImportProcess.objects.filter(user=server.user, servername=server.servername).delete()
            PortSecurity.objects.filter(user=server.user, servername=server.servername).delete()
            PortIpSegment.objects.filter(user=server.user, servername=server.servername).delete()
            SuperList.objects.filter(user=server.user, servername=server.servername).delete()
            OutsideDevice.objects.filter(user=server.user, servername=server.servername).delete()
            ServerTable.objects.filter(id=selected).delete()

        # 模糊搜索
        if searchname:
            serverinfo = ServerTable.objects.filter(user=request.user,servername__contains=searchname)
        else:
            serverinfo = ServerTable.objects.filter(user=request.user)

    else:
        status = request.GET.get('status') 
        if status:
            logging.debug(status)
            serverinfo = ServerTable.objects.filter(user=request.user,serverstatus=status)
        else:
            serverinfo = ServerTable.objects.filter(user=request.user)

    strategies = []
    for server in serverinfo:
        strategyname =  server.strategyname
        if not strategyname:
            strategies.append('')
        else:
            try:
                strategy = Strategy.objects.get(strategyname = strategyname)
                if not strategy:
                    server.strategyname = '自定义策略'
                    strategies.append('')
                else:
                    strategies.append(strategy.id)
            except:
                server.strategyname = ""
                strategies.append('')


    return render(request, 'cloundset/servermanage.html', {'section':'securityset','serverinfo':serverinfo,'strategies':strategies,'searchname':searchname,'servergroups':servergroups})

# 移动服务器到分组    
def movetogroup(serverarry,user,togroup):
    for server in serverarry:
        serverid = server.replace('select_','')
        if 'Un_Group' == togroup:
            groupcode = 'Un_Group'
        else:
            group = ServerGroup.objects.get(user=user,groupname=togroup)
            groupcode = group.groupcode
        ServerTable.objects.filter(user=user,id=serverid).update(servergroup=groupcode)
        serverinfo = ServerTable.objects.filter(user=user,id=serverid)
        logging.debug(serverinfo)

# 删除服务器分组        
def delgroup(grouparry,user):
    for group in grouparry:
        if group == 'all':
            servergroups = ServerGroup.objects.filter(user=user)
            for servergroup in servergroups:
                serverinfo = ServerTable.objects.filter(user=user, servergroup=servergroup.groupcode)
                for server in serverinfo:
                    server.servergroup = 'Un_Group'
                    server.save()

            ServerGroup.objects.filter(user=user).delete()
            return True
        elif '' != group:
            groupid = group.replace('del_','')
            logging.debug(groupid)
            groups = ServerGroup.objects.filter(id=groupid)
            if not groups:
                return False
            servergroup = ServerGroup.objects.get(id=groupid)
            serverinfo = ServerTable.objects.filter(user=user,servergroup=servergroup.groupcode)
            for server in serverinfo:
                server.servergroup = 'Un_Group'
                server.save()
            ServerGroup.objects.filter(id=groupid).delete()
            servergroup = ServerGroup.objects.filter(id=groupid)
            if servergroup:
                return False
    return True
        
# 删除服务器  
def delserverfunc(serverarry,user):
    for server in serverarry:
        serverid = server.replace('select_','')
        ServerTable.objects.filter(user=user,id=serverid).delete()
    
 # 分组管理 
@login_required
def groupmanage(request):
    serverinfo = ServerTable.objects.filter(user=request.user)
    servergroups = ServerGroup.objects.filter(user=request.user)
    if request.method=="POST":
        logging.debug('groupmanage_debug')
        togroup = request.POST.get("movetogroup")
        toUnGroup = request.POST.get("movetoUnGroup")
        selectedserver = request.POST.getlist("serverIds")

        # 移动到未分组
        if selectedserver and toUnGroup:
            movetogroup(selectedserver, request.user, 'Un_Group')
        
        # 是否服务器有勾选
        if selectedserver and togroup:
            movetogroup(selectedserver,request.user,togroup)

    return render(request, 'cloundset/groupmanage.html', {'section':'securityset','servergroups':servergroups,'serverinfo':serverinfo})

# 添加服务器    
@login_required
def addserver(request):
    return render(request, 'cloundset/addserver.html', {'section':'securityset'})

# 显示单台服务器
@login_required
def singleserver(request):
    serverid = request.GET.get('serverid')
    servergroups = ServerGroup.objects.filter(user=request.user)
    # try:
    server = ServerTable.objects.get(user=request.user, id=serverid)
    lastlogin = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    dateinstall = getYearMonthDate(server.protected_days)
    datenow = getYearMonthDate(lastlogin)
    days = (datenow - dateinstall).days+1

    return render(request, 'cloundset/singleserver.html', {'section':'securityset','server':server,'servergroups':servergroups,'protect_days':days})
    # except:
    #     return HttpResponse('Nonexist Server')

# 保存添加IP拦截监控列表
def saveinterceptip(request):
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        server = ServerTable.objects.get(serverip=ip)

        # for param in params:
        ip = params['ip']
        port = params['port']
        postion = params['local']
        remaintime = params['second']
        intercepttype = params['attacktype']

        InterceptIP.objects.create(user=server.user,servername=server.servername, ip=ip, port=port,type='BLOCK_IP',postion=postion,remaintime=remaintime,intercepttype=intercepttype)
        countdown(server.user,server.servername,ip)

        return HttpResponse('success')

# 装饰器
def async(f):
    def wrapper(*args, **kwargs):
        thr = Thread(target = f, args = args, kwargs = kwargs)
        thr.start()
    return wrapper

@async
def countdown(user,servername,ip):
    t = int(InterceptIP.objects.get(user=user,servername=servername, ip=ip).remaintime)
    while t > 0:
        sleep(1)
        t -= 1
        InterceptIP.objects.filter(user=user,servername=servername, ip=ip).update(remaintime = str(t))
        t = int(InterceptIP.objects.get(user=user,servername=servername, ip=ip).remaintime)
    InterceptIP.objects.filter(user=user,servername=servername, ip=ip).delete()

# 删除选中的拦截IP
def delInterceptIP(request):
    interceptipid = request.GET.get('selectInterceptIPid')
    idarray = interceptipid.split(';')

    try:
        for id in idarray:
            if id:
                InterceptIP.objects.filter(id=id).delete()
        return HttpResponse('success')
    except:
        return HttpResponse('fail')

# 获取拦截ip列表中剩余时间
def getremaintime(request):
    interceptipid = request.GET.get('interceptipid')
    try:
        interceptip = InterceptIP.objects.get(id=interceptipid)
        ret = int(interceptip.remaintime)
        response = '{"id":%d,"remain":%d}' % (int(interceptipid),ret)
        return HttpResponse(response)
    except:
        response = '{"id":%d,"remain":0}' % (int(interceptipid))
        return HttpResponse(response)

# 移动拦截ip列表
def changeinterceptip(request):
    interceptipid = request.GET.get('selectinterceptipid')
    newtype = request.GET.get('type')
    idarray= interceptipid.split(';')

    for id in idarray:
        if id:
            InterceptIP.objects.filter(id=id).update(type=newtype,remaintime=50)

    return HttpResponse('success')

@login_required
def protectset(request):
    serverid = request.GET.get('serverid')
    logging.debug('protectset')
    logging.debug(serverid)
    profile = Profile.objects.filter(user=request.user)
    server = ServerTable.objects.get(id=serverid)
    logging.debug(server)
    file_prot_sysrules = UserRule.objects.filter(servername=server.servername,user=request.user, featuremodule='file_prot_sys')
    file_prot_userrules = UserRule.objects.filter(servername=server.servername,user=request.user,featuremodule='file_prot' )
    registry_prot_sysrules = UserRule.objects.filter(servername=server.servername, user=request.user,featuremodule='registry_prot_sys')
    registry_prot_userrules = UserRule.objects.filter(servername=server.servername, user=request.user,featuremodule='registry_prot')
    importprocesses = ImportProcess.objects.filter(user=server.user, servername=server.servername)
    whitelists = WhiteList.objects.filter(user=server.user,servername=server.servername)
    superlists = SuperList.objects.filter(user=server.user,servername=server.servername)
    apps = AppControl.objects.filter(user=server.user,servername=server.servername)
    usergroups = AccoutProt.objects.filter(user=server.user,servername=server.servername)
    servergateways = ServerGateway.objects.filter(user=server.user,servername=server.servername)
    interceptips = InterceptIP.objects.filter(user=server.user, servername=server.servername)
    apptypearray = []
    for app in apps:
        apptype = app.apptype
        if not apptype in apptypearray:
            apptypearray.append(apptype)

    devices = OutsideDevice.objects.filter(user=server.user,servername=server.servername)
    devicetypearray = []
    for device in devices:
        devicetype = device.devicetype
        if not devicetype in devicetypearray:
            devicetypearray.append(devicetype)

    exceptval = ''
    ports = PortSecurity.objects.filter(user=server.user,servername=server.servername)
    for port in ports:
        exceptval = ''
        excevalue = port.exception
        if excevalue.endswith(';'):
            exceptval = port.exception;
        elif '' != excevalue:
            exceptval = port.exception + ';';
        segments = PortIpSegment.objects.filter(servername=server.servername,user=server.user,port = port.port, protocol = port.protocol)
        for segment in segments:
            exceptval += segment.startip + '-' + segment.endip + ';';
        port.exceptionvalue = exceptval
        port.save()

    portsegments = PortIpSegment.objects.filter(user=server.user,servername=server.servername)
    # gateways = CustomizeGateway.objects.filter(servername=server.servername)
    netfirewall = NetFirewall.objects.get(user=server.user,servername=server.servername)
    urlwhitelists = UrlWhiteList.objects.filter(user=server.user,servername=server.servername)

    return render(request, 'cloundset/protectset.html', {'section':'securityset','server':server,'file_prot_sysrules':file_prot_sysrules,'file_prot_userrules':file_prot_userrules,'registry_prot_sysrules':registry_prot_sysrules,'registry_prot_userrules':registry_prot_userrules,'importprocesses':importprocesses,'whitelists':whitelists,'superlists':superlists,'interceptips':interceptips,'apps':apps,'apptypearray':apptypearray,'devices':devices,'devicetypearray':devicetypearray,'ports':ports,'netfirewall':netfirewall,'urlwhitelists':urlwhitelists,'usergroups':usergroups,'portsegments':portsegments,'profilephone':profile[0].alarm_phone,'gateways':servergateways})
    
@login_required
def sysfirewall(request):
    serverid = request.GET.get('serverid')
    logging.debug('sysfirewall')
    logging.debug(serverid)    
    server = ServerTable.objects.get(id=serverid)
    logging.debug(server)
    return render(request, 'cloundset/sysfirewall.html', {'section':'securityset','server':server})

@login_required
def serverimprove(request):
    serverid = request.GET.get('serverid')
    logging.debug('serverimprove')
    logging.debug(serverid)
    server = ServerTable.objects.get(id=serverid)
    logging.debug(server)
    return render(request, 'cloundset/serverimprove.html', {'section':'securityset','server':server})
    
@login_required
def buy(request):
    users = User.objects.filter(is_active=True)
    return render(request, 'account/buy.html', {'section':'people','users':users})
                                                      
@login_required
def signout(request):
    logout(request)
    return render(request, 'account/index.html', {'section':'people'})

@login_required
def notice(request):
    logging.debug("notice-debug") 
    server = ''
    selectedserver = 'all'
    selectedmethod = 'all'
    startday = ''
    endday = ''
    notices = ServerNotice.objects.filter(user=request.user).order_by('-noticedate')
    serverinfo = ServerTable.objects.filter(user=request.user)
    if request.method=="POST":   
        server = request.POST.getlist("server")[0]
        method = request.POST.getlist("method")[0]
        startday = request.POST.getlist("startDateStr")[0]
        endday = request.POST.getlist("endDateStr")[0]

        startdayarray = startday.split('-')
        enddayarray = endday.split('-')
        datefrom = datetime.datetime(int(startdayarray[0]), int(startdayarray[1]), int(startdayarray[2]), 0, 0)
        dateto = datetime.datetime(int(enddayarray[0]), int(enddayarray[1]), int(enddayarray[2]), 23, 59)

        delselected = request.POST.getlist("delselected")
        logging.debug(delselected)
        if delselected:
            logging.debug('删除')
            selecteds = request.POST.getlist("selectdel")
            if selecteds:
                for selected in selecteds:
                    logging.debug(selected)
                    ServerNotice.objects.filter(id=selected).delete()
                    
            notices = ServerNotice.objects.filter(user=request.user).order_by('-noticedate')
            return render(request, 'cloundset/notification.html', {'section':'notice','notices':notices,'serverinfo':serverinfo,'selectedserver':selectedserver,'selectedmethod':selectedmethod,'startday':startday,'endday':endday})
                
        selectedserver = server
        selectedmethod = method
        
        if server != 'all':
            if method != 'all' :
                notices = ServerNotice.objects.filter(user=request.user,servername=server,noticemethod=method,noticedate__range=(datefrom, dateto)).order_by('-noticedate')
            else:
                notices = ServerNotice.objects.filter(user=request.user,servername=server,noticedate__range=(datefrom, dateto)).order_by('-noticedate')
        else:
            if method != 'all' :
                notices = ServerNotice.objects.filter(user=request.user,noticemethod=method,noticedate__range=(datefrom, dateto)).order_by('-noticedate')
            else:
                notices = ServerNotice.objects.filter(user=request.user,noticedate__range=(datefrom, dateto)).order_by('-noticedate')
                
        
    logging.debug(notices)     
    return render(request, 'cloundset/notification.html', {'section':'notice','notices':notices,'serverinfo':serverinfo,'selectedserver':selectedserver,'selectedmethod':selectedmethod,'startday':startday,'endday':endday})

# 保存修改的异地登录设置
def saveremotelogin(request):
    serverid = request.GET['serverid']
    commonlogina = request.GET['commonlogina']
    commonloginb = request.GET['commonloginb']
    remoteloginnotice = request.GET['remoteloginnotice']
    remoteloginway = 0

    if 'remotelogin_message' in remoteloginnotice:
        remoteloginway +=1
    if 'remotelogin_email' in remoteloginnotice:
        remoteloginway +=2

    try:
        if serverid:
            ServerTable.objects.filter(user=request.user, id=serverid).update(commonlogincitya=commonlogina,commonlogincityb=commonloginb,remoteloginnotice=remoteloginway)
        else:
            strategyid = request.GET['strategyid']
            Strategy.objects.filter(user=request.user, id=strategyid).update(commonlogincitya=commonlogina,commonlogincityb=commonloginb,remoteloginnotice=remoteloginway)

        return HttpResponse("success")
    except:
        return HttpResponse("fail")

# 保存客户端的报警日志日志
def savelog(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        param = req['param']
        server = ServerTable.objects.get(serverip=ip)
        type =  param['attacktype']
        if('ARP对外攻击' == type):
            server.ARPoutattack += 1
            server.attackcount += 1
        if ('ARP欺骗攻击' == type):
            server.ARPfobattack += 1
            server.attackcount += 1
        if ('IP冲突攻击' == type):
            server.ARPIPclashattack += 1
            server.attackcount += 1
        if ('DDOS扫描攻击' == type):
            server.DDosscanattack += 1
            server.attackcount += 1
        if ('ICMP攻击' == type):
            server.DDosICMPattack += 1
            server.attackcount += 1
        if ('UDP攻击' == type):
            server.DDosUDPattack += 1
            server.attackcount += 1
        if ('CC攻击' == type):
            server.WebCCattack += 1
            server.attackcount += 1
        if ('远程桌面暴力破解' == type):
            server.APPremotedeskattack += 1
            server.attackcount += 1
        if ('SYN攻击' == type):
            server.SYNattack += 1
            server.attackcount += 1
        if ('FTP暴力破解' == type):
            server.Ftpattack += 1
            server.attackcount += 1
        if ('MYSQL暴力破解' == type):
            server.MySqlattack += 1
            server.attackcount += 1
        if ('MSSQL暴力破解' == type):
            server.MSSqlattack += 1
            server.attackcount += 1
        server.save()

        # ServerNotice.objects.all().delete()

        notices = ServerNotice.objects.all()
        n = len(notices)
        if n > 999:
            lastid = notices[n-999].id
            ServerNotice.objects.filter(id__lt=lastid).delete()

        ServerNotice.objects.create(user=server.user,servername=server.servername,noticedate=param['datetime'],noticereason=param['logtype'],noticetype=type,defendresult=param['defendresult'],noticecontent=param['loginfo'])
        return HttpResponse("success")

# 保存客户端的操作日志
def saveactionlog(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        param = req['param']
        server = ServerTable.objects.get(serverip=ip)

        logs = ActionLog.objects.all()
        n = len(logs)
        if n > 999:
            lastid = logs[n-999].id
            ActionLog.objects.filter(id__lt=lastid).delete()

        ActionLog.objects.create(user=server.user,servername=server.servername,date=param['datetime'],actionmodel=param['logtype'],actioncontent=param['loginfo'])
        return HttpResponse("success")

# 修改流量统计数据
def changNetFlow(oldNetFlow,newFlow):
    netFlowarray = oldNetFlow.split(';')
    if len(netFlowarray) > 24:
        del netFlowarray[0]
    floatFlow = float(newFlow)
    tmp = floatFlow/1000000
    netFlowarray.append(tmp)

    newNetFlow = ''
    for netflow in netFlowarray:
        if netflow != '':
            newNetFlow += str(netflow)
            newNetFlow += ';'
    return newNetFlow

# 保存客户端的网络流量统计
def savenetworkcount(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']


        param = req['param']
        server = ServerTable.objects.get(serverip=ip)

        server.networkDownFlow = changNetFlow(server.networkDownFlow, param['DownFlow'])
        server.networkUpFlow = changNetFlow(server.networkUpFlow, param['UpFlow'])
        server.save()

        return HttpResponse("success")

# 操作日志
@login_required
def actionlog(request):
    logging.debug("notice-debug") 
    server = ''
    selectedserver = 'all'
    selectedmodel = 'all'
    startday = ''
    endday = ''
    actionlogs = ActionLog.objects.filter(user=request.user).order_by('-date')
    serverinfo = ServerTable.objects.filter(user=request.user)
    if request.method == "POST":
        server = request.POST.getlist("server")[0]
        model = request.POST.getlist("model")[0]

        startday = request.POST.getlist("startDateStr")[0]
        endday = request.POST.getlist("endDateStr")[0]
        startdayarray = startday.split('-')
        enddayarray = endday.split('-')
        datefrom = datetime.datetime(int(startdayarray[0]), int(startdayarray[1]), int(startdayarray[2]), 0, 0)
        dateto = datetime.datetime(int(enddayarray[0]), int(enddayarray[1]), int(enddayarray[2]), 23, 59)

        delselected = request.POST.getlist("delselected")
        logging.debug(delselected)
        if delselected:
            logging.debug('删除')
            selecteds = request.POST.getlist("selectdel")
            if selecteds:
                for selected in selecteds:
                    logging.debug(selected)
                    ActionLog.objects.filter(id=selected).delete()

            actionlogs = ActionLog.objects.filter(user=request.user).order_by('-date')
            return render(request, 'cloundset/actionlog.html',
                              {'section': 'notice', 'actionlogs': actionlogs, 'serverinfo': serverinfo,
                               'selectedserver': selectedserver, 'selectedmodel': selectedmodel, 'user': request.user,
                               'startday': startday, 'endday': endday})

        selectedserver = server
        selectedmodel = model

        if server != 'all':
            if model != 'all':
                actionlogs = ActionLog.objects.filter(user=request.user, servername=server, actionmodel=model, date__range=(datefrom, dateto)).order_by('-date')
            else:
                actionlogs = ActionLog.objects.filter(user=request.user, servername=server,date__range=(datefrom, dateto)).order_by('-date')
        else:
            if model != 'all':
                actionlogs = ActionLog.objects.filter(user=request.user, actionmodel=model,date__range=(datefrom, dateto)).order_by('-date')
            else:
                actionlogs = ActionLog.objects.filter(user=request.user,date__range=(datefrom, dateto)).order_by('-date')


    return render(request, 'cloundset/actionlog.html', {'section':'notice','actionlogs':actionlogs,'serverinfo':serverinfo,'selectedserver':selectedserver,'selectedmodel':selectedmodel,'user':request.user,'startday':startday,'endday':endday})

    
@login_required
def user_detail(request, username):
    user = get_object_or_404(User, username=username, is_active=True)
    return render(request, 'account/detail.html', {'section':'people','user':user})

# 连接客户端修改数据库
def connectclient(request):
    logging.debug("connectclient")

    try:
        # conn = MySQLdb.connect(host = '192.168.60.27',user = 'user',db = 'radarsys',passwd = 'password',port = 3306, charset = "utf8")
        conn = MySQLdb.connect(host='192.168.60.26', user='root', db='sysfirewall', passwd='', port=3309, charset="utf8")
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION();")
        values = cursor.fetchall()
        cursor.close()
        conn.close()
    except Exception as e:
        err = e
    return HttpResponse("success")


# 获取发出请求的客户端的IP地址
def GetRequestIP(request):
    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']

    return ip


# 保存客户端设置中心的修改
def onclientchange(request):
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip= GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        try:
            method = req['method']
            params = req['param']
            if 'sysfirewallmaincfig' == method:
                if 'FILE' in params:
                    ServerTable.objects.filter(serverip=ip).update(file_prot=req['param']['FILE'])
                # if 'ACCOUNT' in params:
                #     server.account_prot = params['ACCOUNT']
                if 'REGISTER' in params:
                    ServerTable.objects.filter(serverip=ip).update(registry_prot=req['param']['REGISTER'])
                if 'PROCESS' in params:
                    ServerTable.objects.filter(serverip=ip).update(process_behavior=req['param']['PROCESS'])
                if 'DEVICE' in params:
                    ServerTable.objects.filter(serverip=ip).update(outside_control=req['param']['DEVICE'])
                if 'REMOTE' in params:
                    ServerTable.objects.filter(serverip=ip).update(remote_login_remind=req['param']['REMOTE'])
                if 'WHITE' in params:
                    ServerTable.objects.filter(serverip=ip).update(whitelist_access_control=req['param']['WHITE'])
            elif 'ControlDev' == method:
                for param in params:
                    index = param['DEVICE']
                    if 0 == index:
                        ServerTable.objects.filter(serverip=ip).update(bluetooth=param['STATUS'])
                    elif 1 == index:
                        ServerTable.objects.filter(serverip=ip).update(opticaldrive=param['STATUS'])
                    elif 2 == index:
                        ServerTable.objects.filter(serverip=ip).update(wirelessdevice=param['STATUS'])
                    elif 3 == index:
                        ServerTable.objects.filter(serverip=ip).update(mobiledevice=param['STATUS'])
            return HttpResponse('success')
        except Exception as e:
            print "onclientchange fail"
            print(e)

        # 加载设置中心页面初始阶段
def loadinstall(server,isserver):
    if isserver:
        ret = '{"account_prot":%d,"file_prot":%d,"registry_prot":%d,"outside_control":%d,"process_behavior":%d,"bluetooth":%d,"opticaldrive":%d,"wirelessdevice":%d,"mobiledevice":%d,"remote_login_remind":%d,"whitelist_access_control":%d,"ARPfirwall":%d,"DDosfirwall":%d,"Web_firwall":%d,"FTP_avoidviolence":%d,"ReDesktop_avoidviolence":%d,"MySQL_avoidviolence":%d,"MSSQL_avoidviolence":%d,"port_security":%d,"forbid_ping":%d,"super_blacklist":%d,"super_whitelist":%d}' % (server.account_prot, server.file_prot, server.registry_prot, server.outside_control, server.process_behavior, server.bluetooth,server.opticaldrive,server.wirelessdevice,server.mobiledevice, server.remote_login_remind, server.whitelist_access_control, server.ARPfirwall, server.DDosfirwall, server.Web_firwall, server.FTP_avoidviolence,server.ReDesktop_avoidviolence, server.MySQL_avoidviolence, server.MSSQL_avoidviolence, server.port_security,server.forbid_ping, server.super_blacklist, server.super_whitelist)
    else:
        ret = '{"account_prot":%d,"file_prot":%d,"registry_prot":%d,"outside_control":%d,"process_behavior":%d,"remote_login_remind":%d,"whitelist_access_control":%d,"ARPfirwall":%d,"DDosfirwall":%d,"Web_firwall":%d,"FTP_avoidviolence":%d,"ReDesktop_avoidviolence":%d,"MySQL_avoidviolence":%d,"MSSQL_avoidviolence":%d,"port_security":%d,"forbid_ping":%d,"super_blacklist":%d,"super_whitelist":%d}' % (server.account_prot, server.file_prot, server.registry_prot, server.outside_control, server.process_behavior,server.remote_login_remind,server.whitelist_access_control, server.ARPfirwall, server.DDosfirwall, server.Web_firwall,server.FTP_avoidviolence, server.ReDesktop_avoidviolence, server.MySQL_avoidviolence,server.MSSQL_avoidviolence, server.port_security, server.forbid_ping, server.super_blacklist,server.super_whitelist)
    return ret

# 初始化设置中心页面
def installsetting(request):
    serverid = request.GET['serverid']
    obj = request.GET['obj']
    logging.debug(obj)
    if not serverid:
        strategyid = request.GET['strategyid']
        strategy = Strategy.objects.get(id=strategyid)
    else:
        logging.debug(serverid)
        server = ServerTable.objects.get(id=serverid)

    if serverid:
        return HttpResponse(loadinstall(server,True))
    else:
        return HttpResponse(loadinstall(strategy,False))

def changevalue(status):
    if status > 0:
        return 'true'
    else:
        return 'false'


# 保存用户设置
def savechange(request):
    logging.debug("savechange")
    serverid = request.GET['serverid']
    obj = request.GET['obj']
    type = request.GET['type']
    logging.debug(obj)
    if not serverid:
        strategyid = request.GET['strategyid']
        strategy = Strategy.objects.get(id=strategyid)
    else:
        logging.debug(serverid)
        server = ServerTable.objects.get(id=serverid)

    if obj != 'all' and type == '':
        if serverid:
            server.strategyname = '自定义模版'
            server.save()
            # 系统预设功能设置-系统防火墙
            # if 'account_prot' == obj:
            #     if server.account_prot:
            #         server.account_prot = False
            #     else:
            #         server.account_prot = True
            #     msg = '{"method": "sysfirewallmaincfig", "param": {"ACCOUNT": %d}}' % (server.account_prot)
            #     if SendToClient(server.serverip, msg, False):
            #         server.save()
            #         ret ='{"account_prot":%d}' % (server.account_prot)
            #         content = '功能：账户保护 修改状态为：%s' % (server.account_prot)
            #         addactionlog(server.user, server.servername, '系统防火墙', content)
            #         return HttpResponse(ret)
            #     else:
            #         return HttpResponse('fail')

            if 'file_prot' == obj:
                if server.file_prot:
                    server.file_prot = False
                else:
                    server.file_prot = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"FILE": %s}}' % (changevalue(server.file_prot))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret ='{"file_prot":%d}' % (server.file_prot)
                    content = '功能：文件保护 修改状态为：%s' % (server.file_prot)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'registry_prot' == obj:
                if server.registry_prot:
                    server.registry_prot = False
                else:
                    server.registry_prot = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"REGISTER": %s}}' % (changevalue(server.registry_prot))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"registry_prot":%d}' % (server.registry_prot)
                    content = '功能：注册表保护 修改状态为：%s' % (server.registry_prot)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'outside_control' == obj:
                if server.outside_control:
                    server.outside_control = False
                else:
                    server.outside_control = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"DEVICE": %s}}' % (changevalue(server.outside_control))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"outside_control":%d}' % (server.outside_control)
                    content = '功能：外围控制 修改状态为：%s' % (server.outside_control)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'process_behavior' == obj:
                if server.process_behavior:
                    server.process_behavior = False
                else:
                    server.process_behavior = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"PROCESS": %s}}' % (
                    changevalue(server.process_behavior))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"process_behavior":%d}' % (server.process_behavior)
                    content = '功能：进程行为控制 修改状态为：%s' % (server.process_behavior)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            # if 'app_control' == obj:
            #     if server.app_control:
            #         server.app_control = False
            #     else:
            #         server.app_control = True
            #     server.save()
            #     ret ='{"app_control":%d}' % (server.app_control)
            #     content = '功能：外围控制 修改状态为：%s' % (server.outside_control)
            #     addactionlog(server.user, server.servername, '系统防火墙', content)
            #     return HttpResponse(ret)

            if 'remote_login_remind' == obj:
                if server.remote_login_remind:
                    server.remote_login_remind = False
                else:
                    server.remote_login_remind = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"REMOTE": %s}}' % (
                    changevalue(server.remote_login_remind))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"remote_login_remind":%d}' % (server.remote_login_remind)
                    content = '功能：异地登录提醒 修改状态为：%s' % (server.remote_login_remind)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')


            if 'whitelist_access_control' == obj:
                if server.whitelist_access_control:
                    server.whitelist_access_control = False
                else:
                    server.whitelist_access_control = True
                msg = '{"method": "sysfirewallmaincfig", "param": {"WHITE": %s}}' % (
                    changevalue(server.whitelist_access_control))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"whitelist_access_control":%d}' % (server.whitelist_access_control)
                    content = '功能：登录保护 修改状态为：%s' % (server.whitelist_access_control)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            # 网络防火墙
            if 'ARPfirwall' == obj:
                if server.ARPfirwall:
                    server.ARPfirwall = False
                else:
                    server.ARPfirwall = True
                msg = '{"method": "netfirewallmaincfig", "param": {"ARPFireWall": %s}}' % (
                    changevalue(server.ARPfirwall))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"ARPfirwall":%d}' % (server.ARPfirwall)
                    content = '功能：ARP防火墙 修改状态为：%s' % (server.ARPfirwall)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'DDosfirwall' == obj:
                if server.DDosfirwall:
                    server.DDosfirwall = False
                else:
                    server.DDosfirwall = True
                msg = '{"method": "netfirewallmaincfig", "param": {"DDosFireWall": %s}}' % (
                    changevalue(server.DDosfirwall))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"DDosfirwall":%d}' % (server.DDosfirwall)
                    content = '功能：DDoS防火墙 修改状态为：%s' % (server.DDosfirwall)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'Web_firwall' == obj:
                if server.Web_firwall:
                    server.Web_firwall = False
                else:
                    server.Web_firwall = True
                msg = '{"method": "netfirewallmaincfig", "param": {"WebFireWall": %s}}' % (
                    changevalue(server.Web_firwall))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"Web_firwall":%d}' % (server.Web_firwall)
                    content = '功能：Web防火墙 修改状态为：%s' % (server.Web_firwall)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'FTP_avoidviolence' == obj:
                if server.FTP_avoidviolence:
                    server.FTP_avoidviolence = False
                else:
                    server.FTP_avoidviolence = True
                msg = '{"method": "netfirewallmaincfig", "param": {"FTPProtect": %s}}' % (
                    changevalue(server.FTP_avoidviolence))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"FTP_avoidviolence":%d}' % (server.FTP_avoidviolence)
                    content = '功能：FTP防暴力破解 修改状态为：%s' % (server.FTP_avoidviolence)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'ReDesktop_avoidviolence' == obj:
                if server.ReDesktop_avoidviolence:
                    server.ReDesktop_avoidviolence = False
                else:
                    server.ReDesktop_avoidviolence = True
                msg = '{"method": "netfirewallmaincfig", "param": {"RemoteProtect": %s}}' % (
                    changevalue(server.ReDesktop_avoidviolence))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"ReDesktop_avoidviolence":%d}' % (server.ReDesktop_avoidviolence)
                    content = '功能：外围控制 修改状态为：%s' % (server.ReDesktop_avoidviolence)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'MySQL_avoidviolence' == obj:
                if server.MySQL_avoidviolence:
                    server.MySQL_avoidviolence = False
                else:
                    server.MySQL_avoidviolence = True
                msg = '{"method": "netfirewallmaincfig", "param": {"MySQLProtect": %s}}' % (
                    changevalue(server.MySQL_avoidviolence))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"MySQL_avoidviolence":%d}' % (server.MySQL_avoidviolence)
                    content = '功能：MySQL防暴力破解 修改状态为：%s' % (server.MySQL_avoidviolence)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'MSSQL_avoidviolence' == obj:
                if server.MSSQL_avoidviolence:
                    server.MSSQL_avoidviolence = False
                else:
                    server.MSSQL_avoidviolence = True
                msg = '{"method": "netfirewallmaincfig", "param": {"MSSQLProtect": %s}}' % (
                    changevalue(server.MSSQL_avoidviolence))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"MSSQL_avoidviolence":%d}' % (server.MSSQL_avoidviolence)
                    content = '功能：MSSQL防暴力破解 修改状态为：%s' % (server.MSSQL_avoidviolence)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            # 端口安全策略
            if 'port_security' == obj:
                if server.port_security:
                    server.port_security = False
                else:
                    server.port_security = True
                msg = '{"method": "netfirewallmaincfig", "param": {"PortPolicy": %s}}' % (
                    changevalue(server.port_security))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"port_security":%d}' % (server.port_security)
                    content = '功能：端口安全策略 修改状态为：%s' % (server.port_security)
                    addactionlog(server.user, server.servername, '端口保护', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'forbid_ping' == obj:
                if server.forbid_ping:
                    server.forbid_ping = False
                else:
                    server.forbid_ping = True
                msg = '{"method": "netfirewallmaincfig", "param": {"ForbidPing": %s}}' % (changevalue(server.forbid_ping))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"forbid_ping":%d}' % (server.forbid_ping)
                    content = '功能：禁止ping本机 修改状态为：%s' % (server.forbid_ping)
                    addactionlog(server.user, server.servername, '端口保护', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'super_blacklist' == obj:
                if server.super_blacklist:
                    server.super_blacklist = False
                else:
                    server.super_blacklist = True
                msg = '{"method": "netfirewallmaincfig", "param": {"BlakcList": %s}}' % (changevalue(server.super_blacklist))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"super_blacklist":%d}' % (server.super_blacklist)
                    content = '功能：超级黑名单 修改状态为：%s' % (server.super_blacklist)
                    addactionlog(server.user, server.servername, '超级黑名单', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            if 'super_whitelist' == obj:
                if server.super_whitelist:
                    server.super_whitelist = False
                else:
                    server.super_whitelist = True
                msg = '{"method": "netfirewallmaincfig", "param": {"WhiteList": %s}}' % (
                    changevalue(server.super_whitelist))
                if SendToClient(server.serverip, msg, False):
                    server.save()
                    ret = '{"super_whitelist":%d}' % (server.super_whitelist)
                    content = '功能：超级白名单 修改状态为：%s' % (server.super_whitelist)
                    addactionlog(server.user, server.servername, '超级白名单', content)
                    return HttpResponse(ret)
                else:
                    return HttpResponse('fail')

            # # 账户保护
            # if 'nochangadmin_pass' == obj:
            #     if server.nochangadmin_pass:
            #         server.nochangadmin_pass = False
            #     else:
            #         server.nochangadmin_pass = True
            #     server.save()
            #     ret ='{"nochangadmin_pass":%d}' % (server.nochangadmin_pass)
            #     content = '功能：账号保护 修改状态为：%s' % (server.outside_control)
            #     addactionlog(server.user, server.servername, '系统防火墙', content)
            #     return HttpResponse(ret)
            #
            # # 账户保护
            # if 'usergroup_prot' == obj:
            #     if server.usergroup_prot:
            #         server.usergroup_prot = False
            #     else:
            #         server.usergroup_prot = True
            #     server.save()
            #     ret = '{"usergroup_prot":%d}' % (server.usergroup_prot)
            #     content = '功能：账号保护 修改状态为：%s' % (server.outside_control)
            #     addactionlog(server.user, server.servername, '系统防火墙', content)
            #     return HttpResponse(ret)

            # 蓝牙设备
            if 'bluetooth' == obj:
                if server.bluetooth:
                    server.bluetooth = False
                else:
                    server.bluetooth = True
                server.save()
                ret = '{"bluetooth":%d}' % (server.bluetooth)
                content = '功能：外围控制 修改状态为：%s' % (server.bluetooth)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse(ret)

            # 光驱
            if 'opticaldrive' == obj:
                if server.opticaldrive:
                    server.opticaldrive = False
                else:
                    server.opticaldrive = True
                server.save()
                ret = '{"opticaldrive":%d}' % (server.opticaldrive)
                content = '功能：外围控制 修改状态为：%s' % (server.opticaldrive)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse(ret)

            # 无线设备
            if 'wirelessdevice' == obj:
                if server.wirelessdevice:
                    server.wirelessdevice = False
                else:
                    server.wirelessdevice = True
                server.save()
                ret = '{"wirelessdevice":%d}' % (server.wirelessdevice)
                content = '功能：外围控制 修改状态为：%s' % (server.wirelessdevice)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse(ret)
                
            # 无线设备
            if 'mobiledevice' == obj:
                if server.mobiledevice:
                    server.mobiledevice = False
                else:
                    server.mobiledevice = True
                server.save()
                ret = '{"mobiledevice":%d}' % (server.mobiledevice)
                content = '功能：外围控制 修改状态为：%s' % (server.mobiledevice)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse(ret)

            server.save()    

        elif strategy:
            # 系统预设功能设置-系统防火墙
            if 'account_prot' == obj:
                if strategy.account_prot:
                    strategy.account_prot = False
                else:
                    strategy.account_prot = True
                strategy.save()
                ret = '{"account_prot":%d}' % (strategy.account_prot)
                return HttpResponse(ret)

            if 'file_prot' == obj:
                if strategy.file_prot:
                    strategy.file_prot = False
                else:
                    strategy.file_prot = True
                strategy.save()
                ret ='{"file_prot":%d}' % (strategy.file_prot)
                return HttpResponse(ret)

            if 'registry_prot' == obj:
                if strategy.registry_prot:
                    strategy.registry_prot = False
                else:
                    strategy.registry_prot = True
                strategy.save()
                ret ='{"registry_prot":%d}' % (strategy.registry_prot)
                return HttpResponse(ret)

            if 'outside_control' == obj:
                if strategy.outside_control:
                    strategy.outside_control = False
                else:
                    strategy.outside_control = True
                strategy.save()
                ret ='{"outside_control":%d}' % (strategy.outside_control)
                return HttpResponse(ret)

            if 'process_behavior' == obj:
                if strategy.process_behavior:
                    strategy.process_behavior = False
                else:
                    strategy.process_behavior = True
                strategy.save()
                ret ='{"process_behavior":%d}' % (strategy.process_behavior)
                return HttpResponse(ret)

            if 'app_control' == obj:
                if strategy.app_control:
                    strategy.app_control = False
                else:
                    strategy.app_control = True
                strategy.save()
                ret ='{"app_control":%d}' % (strategy.app_control)
                return HttpResponse(ret)

            if 'remote_login_remind' == obj:
                if strategy.remote_login_remind:
                    strategy.remote_login_remind = False
                else:
                    strategy.remote_login_remind = True
                strategy.save()
                ret ='{"remote_login_remind":%d}' % (strategy.remote_login_remind)
                return HttpResponse(ret)

            if 'whitelist_access_control' == obj:
                if strategy.whitelist_access_control:
                    strategy.whitelist_access_control = False
                else:
                    strategy.whitelist_access_control = True
                strategy.save()
                ret ='{"whitelist_access_control":%d}' % (strategy.whitelist_access_control)
                return HttpResponse(ret)

            # 网络防火墙
            if 'ARPfirwall' == obj:
                if strategy.ARPfirwall:
                    strategy.ARPfirwall = False
                else:
                    strategy.ARPfirwall = True
                strategy.save()
                ret ='{"ARPfirwall":%d}' % (strategy.ARPfirwall)
                return HttpResponse(ret)

            if 'DDosfirwall' == obj:
                if strategy.DDosfirwall:
                    strategy.DDosfirwall = False
                else:
                    strategy.DDosfirwall = True
                strategy.save()
                ret ='{"DDosfirwall":%d}' % (strategy.DDosfirwall)
                return HttpResponse(ret)

            if 'Web_firwall' == obj:
                if strategy.Web_firwall:
                    strategy.Web_firwall = False
                else:
                    strategy.Web_firwall = True
                strategy.save()
                ret ='{"Web_firwall":%d}' % (strategy.Web_firwall)
                return HttpResponse(ret)

            if 'FTP_avoidviolence' == obj:
                if strategy.FTP_avoidviolence:
                    strategy.FTP_avoidviolence = False
                else:
                    strategy.FTP_avoidviolence = True
                strategy.save()
                ret ='{"FTP_avoidviolence":%d}' % (strategy.FTP_avoidviolence)
                return HttpResponse(ret)

            if 'ReDesktop_avoidviolence' == obj:
                if strategy.ReDesktop_avoidviolence:
                    strategy.ReDesktop_avoidviolence = False
                else:
                    strategy.ReDesktop_avoidviolence = True
                strategy.save()
                ret ='{"ReDesktop_avoidviolence":%d}' % (strategy.ReDesktop_avoidviolence)
                return HttpResponse(ret)

            if 'MySQL_avoidviolence' == obj:
                if strategy.MySQL_avoidviolence:
                    strategy.MySQL_avoidviolence = False
                else:
                    strategy.MySQL_avoidviolence = True
                strategy.save()
                ret ='{"MySQL_avoidviolence":%d}' % (strategy.MySQL_avoidviolence)
                return HttpResponse(ret)

            if 'MSSQL_avoidviolence' == obj:
                if strategy.MSSQL_avoidviolence:
                    strategy.MSSQL_avoidviolence = False
                else:
                    strategy.MSSQL_avoidviolence = True
                strategy.save()
                ret ='{"MSSQL_avoidviolence":%d}' % (strategy.MSSQL_avoidviolence)
                return HttpResponse(ret)

            # 端口安全策略
            if 'port_security' == obj:
                if strategy.port_security:
                    strategy.port_security = False
                else:
                    strategy.port_security = True
                strategy.save()
                ret ='{"port_security":%d}' % (strategy.port_security)
                return HttpResponse(ret)

            if 'forbid_ping' == obj:
                if strategy.forbid_ping:
                    strategy.forbid_ping = False
                else:
                    strategy.forbid_ping = True
                strategy.save()
                ret ='{"forbid_ping":%d}' % (strategy.forbid_ping)
                return HttpResponse(ret)

            if 'super_blacklist' == obj:
                if strategy.super_blacklist:
                    strategy.super_blacklist = False
                else:
                    strategy.super_blacklist = True
                strategy.save()
                ret ='{"super_blacklist":%d}' % (strategy.super_blacklist)
                return HttpResponse(ret)

            if 'super_whitelist' == obj:
                if strategy.super_whitelist:
                    strategy.super_whitelist = False
                else:
                    strategy.super_whitelist = True
                strategy.save()
                ret ='{"super_whitelist":%d}' % (strategy.super_whitelist)
                return HttpResponse(ret)

            strategy.save()



    ret = '{'
    # 文件保护-自定义规则-一键开启关闭
    if 'file_prot' in obj:
        if serverid:
            file_prot_userrules = UserRule.objects.filter(servername=server.servername,featuremodule='file_prot')
        elif strategy:
            file_prot_userrules = UserRule.objects.filter(servername=strategy.strategyname,featuremodule='file_prot')
        for file_prot_userrule in file_prot_userrules:
            if 'file_prot_openall' == obj:
                file_prot_userrule.rulestatus = True
            elif 'file_prot_closeall' == obj:
                file_prot_userrule.rulestatus = False
            file_prot_userrule.save()

    # 文件保护-系统规则-一键开启关闭
    if 'file_prot_sys' in obj:
        if serverid:
            file_prot_userrules = UserRule.objects.filter(servername=server.servername,
                                                          featuremodule='file_prot_sys')
        elif strategy:
            file_prot_userrules = UserRule.objects.filter(servername=strategy.strategyname,
                                                          featuremodule='file_prot_sys')
        for file_prot_userrule in file_prot_userrules:
            if 'file_prot_sysopenall' == obj:
                file_prot_userrule.rulestatus = True
            elif 'file_prot_syscloseall' == obj:
                file_prot_userrule.rulestatus = False
            file_prot_userrule.save()

    # 注册表保护-自定义规则-一键开启关闭
    if 'registry_prot' in obj:
        if serverid:
            registry_prot_userrules = UserRule.objects.filter(servername=server.servername, featuremodule='registry_prot')
        elif strategy:
            registry_prot_userrules = UserRule.objects.filter(servername=strategy.strategyname, featuremodule='registry_prot')
        for registry_prot_userrule in registry_prot_userrules:
            if 'registry_prot_openall' == obj:
                registry_prot_userrule.rulestatus = True
            elif 'registry_prot_closeall' == obj:
                registry_prot_userrule.rulestatus = False
            registry_prot_userrule.save()

    # 注册表保护-系统规则-一键开启关闭
    if 'registry_prot' in obj:
        if serverid:
            registry_prot_userrules = UserRule.objects.filter(servername=server.servername,
                                                              featuremodule='registry_prot_sys')
        elif strategy:
            registry_prot_userrules = UserRule.objects.filter(servername=strategy.strategyname,
                                                              featuremodule='registry_prot_sys')
        for registry_prot_userrule in registry_prot_userrules:
            if 'registry_prot_openallsys' == obj:
                registry_prot_userrule.rulestatus = True
            elif 'registry_prot_closeallsys' == obj:
                registry_prot_userrule.rulestatus = False
            registry_prot_userrule.save()
            
    # 自定义规则
    userret = '{'
    i = 0
    if 'all' != obj and 'file_prot' == type or 'registry_prot' == type:
        # 选取规则表中关于该服务器的规则内容
        if serverid:
            userrule = UserRule.objects.get(user=server.user, servername=server.servername,rulename=obj)
        elif strategy:
            userrule = UserRule.objects.get(user=strategy.user, servername=strategy.strategyname)

        if not userrule:
            return HttpResponse('fail')

        if userrule.rulestatus:
            userrule.rulestatus = False
        else:
            userrule.rulestatus = True
        userrule.save()

        if 'sys' in userrule.featuremodule:
            tmp = '{"sysruleid_%d":%d}' % (userrule.id, userrule.rulestatus)
        else:
            tmp = '{"userruleid_%d":%d}' % (userrule.id, userrule.rulestatus)
        return HttpResponse(tmp)
    else:
        # 选取规则表中关于该服务器的规则内容
        if serverid:
            userrules = UserRule.objects.filter(user=server.user, servername=server.servername)
        elif strategy:
            userrules = UserRule.objects.filter(user=strategy.user, servername=strategy.strategyname)
        for userrule in userrules:
            i += 1
            if i == len(userrules) and 'all' != obj:
                if 'sys' in userrule.featuremodule:
                    tmp = '"sysruleid_%d":%d' % (userrule.id, userrule.rulestatus)
                else:
                    tmp = '"userruleid_%d":%d' % (userrule.id, userrule.rulestatus)
            else:
                if 'sys' in userrule.featuremodule:
                    tmp = '"sysruleid_%d":%d,' % (userrule.id, userrule.rulestatus)
                else:
                    tmp = '"userruleid_%d":%d,' % (userrule.id, userrule.rulestatus)
            userret += tmp
            ret += tmp

    if 'file_prot' in obj or 'registry_prot' in obj or 'file_prot' == type or 'registry_prot' == type:
        userret += '}'
        return HttpResponse(userret)

    # # 账户保护-一键开启关闭
    # if 'account_prot' in obj:
    #     if serverid:
    #         usergroups = AccoutProt.objects.filter(servername=server.servername)
    #     elif strategy:
    #         usergroups = AccoutProt.objects.filter(servername=strategy.strategyname)
    #     for usergroup in usergroups:
    #         if 'account_prot_openall' == obj:
    #             usergroup.usergroupstatus = True
    #         elif 'account_prot_closeall' == obj:
    #             usergroup.usergroupstatus = False
    #         usergroup.save()
    #
    #
    # # 账户保护
    # accountprotret = '{'
    # if obj != 'all' and 'account_prot' == type:
    #     if serverid:
    #         usergroup = AccoutProt.objects.get(servername=server.servername,user=server.user,usergroup=obj)
    #     elif strategy:
    #         usergroup = AccoutProt.objects.get(servername=strategy.strategyname,user=strategy.user,usergroup=obj)
    #
    #     if not usergroup:
    #         return HttpResponse('fail')
    #
    #     if usergroup.usergroupstatus:
    #         usergroup.usergroupstatus = False
    #     else:
    #         usergroup.usergroupstatus = True
    #     usergroup.save()
    #
    #     tmp = '{"accountprot_%d":%d}' % (usergroup.id, usergroup.usergroupstatus)
    #     return HttpResponse(tmp)
    # else:
    #     if serverid:
    #         usergroups = AccoutProt.objects.filter(servername=server.servername,user=server.user)
    #     elif strategy:
    #         usergroups = AccoutProt.objects.filter(servername=strategy.strategyname,user=strategy.user)
    #     for usergroup in usergroups:
    #         if usergroup.usergroup == obj:
    #             if usergroup.usergroupstatus:
    #                 usergroup.usergroupstatus = False
    #             else:
    #                 usergroup.usergroupstatus = True
    #         usergroup.save()
    #
    #
    #         tmp = '"accountprot_%s":%d,' % (usergroup.id, usergroup.usergroupstatus)
    #         accountprotret += tmp
    #         ret += tmp
    #
    # accountprotret += '}'
    # if 'account_prot' in obj or 'account_prot' == type:
    #     return HttpResponse(accountprotret)


    # 获取白名单列表
    whitelisttret = '{'
    if serverid:
        whitelists = WhiteList.objects.filter(servername=server.servername)
    elif strategy:
        whitelists = WhiteList.objects.filter(servername=strategy.strategyname)
    n = 0
    for whitelist in whitelists:
        if whitelist.whitelist == obj:
            if whitelist.status:
                whitelist.status = False
            else:
                whitelist.status = True
        whitelist.save()

        n += 1
        if n == len(whitelists):
            tmp = '"whitelist_%s":%d' % (whitelist.id, whitelist.status)
        else:
            tmp = '"whitelist_%s":%d,' % (whitelist.id, whitelist.status)
        ret += tmp
        whitelisttret += tmp

    ret += '}'
    whitelisttret += '}'
    if 'whitelist_prot' == type:
        return HttpResponse(whitelisttret)
    return HttpResponse(ret)

def changeValue(status):
    if status:
        return 'true'
    else:
        return 'false'

# 移动选中的服务器到安全策略
def moverserverto(request):
    logging.debug("moverserverto")
    selectedserver = request.GET['selectedserver']
    strategyname = request.GET['strategy']
    obj = request.GET['obj']

    strategy = Strategy.objects.get(strategyname=strategyname, user=request.user)
    if 'in' == obj:
        sysfireset = '{"method": "sysfirewallmaincfig", "param": {"FILE": %s,"REGISTER": %s,"DEVICE": %s,"PROCESS": %s,"REMOTE": %s,"WHITE": %s} }' % (changeValue(strategy.file_prot), changeValue(strategy.registry_prot), changeValue(strategy.outside_control),changeValue(strategy.process_behavior), changeValue(strategy.remote_login_remind), changeValue(strategy.whitelist_access_control))
        netfireset = '{"method": "netfirewallmaincfig", "param": {"ARPFireWall": %s,"DDosFireWall": %s,"WebFireWall": %s,"FTPProtect": %s,"RemoteProtect": %s,"MySQLProtect": %s,"MSSQLProtect": %s,"PortPolicy": %s,"ForbidPing": %s,"BlakcList": %s,"WhiteList": %s} }' % (changeValue(strategy.ARPfirwall), changeValue(strategy.DDosfirwall), changeValue(strategy.Web_firwall), changeValue(strategy.FTP_avoidviolence),changeValue(strategy.ReDesktop_avoidviolence), changeValue(strategy.MySQL_avoidviolence), changeValue(strategy.MSSQL_avoidviolence),changeValue(strategy.port_security), changeValue(strategy.forbid_ping), changeValue(strategy.super_blacklist), changeValue(strategy.super_whitelist))
    elif 'out' == obj:
        sysfireset = '{"method": "sysfirewallmaincfig", "param": {"FILE": false,"REGISTER": false,"DEVICE": false,"PROCESS": false,"REMOTE": false,"WHITE": false}}'
        netfireset = '{"method": "netfirewallmaincfig", "param": {"ARPFireWall": false,"DDosFireWall": false,"WebFireWall": false,"FTPProtect": false,"RemoteProtect": false,"MySQLProtect": false,"MSSQLProtect": false,"ForbidPing": false,"PortPolicy": false,"BlakcList": false,"WhiteList": false} }'

    try:
        serverarray = selectedserver.split(';')
        for serverid in serverarray:
            if serverid:
                server = ServerTable.objects.get(id=serverid)
                if 'in' == obj:
                    if SendToClient(server.serverip,sysfireset,False) and SendToClient(server.serverip,netfireset,False):
                        ServerTable.objects.filter(user=request.user,id=serverid).update(strategyname=strategy.strategyname,file_prot=strategy.file_prot,registry_prot=strategy.registry_prot,process_behavior=strategy.process_behavior,outside_control=strategy.outside_control,app_control=strategy.app_control,remote_login_remind=strategy.remote_login_remind,whitelist_access_control=strategy.whitelist_access_control,ARPfirwall=strategy.ARPfirwall,DDosfirwall=strategy.DDosfirwall,Web_firwall=strategy.Web_firwall,FTP_avoidviolence=strategy.FTP_avoidviolence,ReDesktop_avoidviolence=strategy.ReDesktop_avoidviolence,MySQL_avoidviolence=strategy.MySQL_avoidviolence,MSSQL_avoidviolence=strategy.MSSQL_avoidviolence,port_security=strategy.port_security,forbid_ping=strategy.forbid_ping,super_blacklist=strategy.super_blacklist,super_whitelist=strategy.super_whitelist)
                    else:
                        return HttpResponse("fail")
                elif 'out' == obj:
                    if SendToClient(server.serverip,sysfireset,False) and SendToClient(server.serverip,netfireset,False):
                        ServerTable.objects.filter(user=request.user,id=serverid).update(strategyname='自定义模版',file_prot=False,registry_prot=False,process_behavior=False,outside_control=False,app_control=False,remote_login_remind=False,whitelist_access_control=False,ARPfirwall=False,DDosfirwall=False,Web_firwall=False,FTP_avoidviolence=False,ReDesktop_avoidviolence=False,MySQL_avoidviolence=False,MSSQL_avoidviolence=False,port_security=False,forbid_ping=False,super_blacklist=False,super_whitelist=False)
                    else:
                        return HttpResponse("fail")

        return HttpResponse("success")
    except:
        return HttpResponse("fail")


# 添加的自定义安全策略
def savestrategy(request):
    logging.debug("savestrategy")

    strategyname = request.GET['strategyname']
    type = request.GET['type']

    strategies =  Strategy.objects.filter(user=request.user,strategyname=strategyname)
    if strategies:
        return HttpResponse("fail")

    Strategy.objects.create(user=request.user, strategyname=strategyname, type=type, time=time.strftime('%Y-%m-%d',time.localtime(time.time())))
    # 创建新的策略模版同时需要做的操作
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止系统目录创建DLL文件', rulepath='C:/Windows', rulestatus=True, forbidaction='check_no_create;', fileprottype=3, refuseExts='C:/Windows')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user, rulename='禁止系统目录创建EXE文件', rulepath='C:/Windows',rulestatus=True, forbidaction='check_no_create;', fileprottype=3, refuseExts='exe')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止目录创建DLL文件', rulepath='C:/Windows/system32', rulestatus=True,forbidaction='check_no_create;', fileprottype=3, refuseExts='dll')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止目录创建EXE文件', rulepath='C:/Windows/system32', rulestatus=True,forbidaction='check_no_create;', fileprottype=3, refuseExts='exe')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user, rulename='禁止执行SC命令', rulepath='C:/Windows/system32', rulestatus=True,forbidaction='check_no_run;', fileprottype=3, refuseFiles='sc')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止劫持HOSTS文件', rulepath='C:/Windows/system32/drivers/etc', rulestatus=True,forbidaction='check_no_write;', fileprottype=3, refuseFiles='hosts')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止sethc.exe和utilman.exe执行', rulepath='C:/Windows/system32', rulestatus=True,forbidaction='check_no_run;', fileprottype=3, refuseFiles='sethc.exe|utilman.exe')
    # # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,
    # #                         rulename='禁止修改Radar目录', rulepath='C:/Program Files/Radar', rulestatus=True,
    # #                         forbidaction='check_no_run;check_no_del;check_no_write;check_no_create;check_no_rea;',                           fileprottype=3, allowProcess='Radar.exe')
    # UserRule.objects.create(servername=strategyname, featuremodule='file_prot_sys', user=request.user,rulename='禁止net命令执行', rulepath='C:/Windows/system32', rulestatus=True,forbidaction='check_no_run;', fileprottype=0, refuseFiles='net|net1')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user,rulename='禁止添加或修改自动运行程序1',rulepath='HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/Run', rulestatus=True,forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user,rulename='禁止添加或修改自动运行程序2',rulepath='HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True,forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='net|net1')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user,rulename='禁止添加或修改自动运行程序1x86',rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run',rulestatus=True,forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user, rulename='禁止添加或修改自动运行程序2x86', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True, forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user, rulename='禁止添加或修改自动运行程序1x64', rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Run', rulestatus=True, forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
    # UserRule.objects.create(servername=strategyname, featuremodule='registry_prot_sys', user=request.user, rulename='禁止添加或修改自动运行程序2x64',rulepath='HKEY_LOCAL_MACHINE/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/RunOnce', rulestatus=True, forbidaction='check_no_write;check_no_create;', fileprottype=1, allowProcess='')
    # NetFirewall.objects.create(user=request.user, servername=strategyname)

    strategys = Strategy.objects.filter(strategyname=strategyname)
    if strategys:
        return HttpResponse("success")
    else:
        return HttpResponse("fail")

# 删除自定义安全策略
def delstrategy(request):
    logging.debug("delstrategy")
    checkedtr = request.GET['checkedtr']

    try:
        checkedtrarry = checkedtr.split(';')
        for strategyid in checkedtrarry:
            if strategyid:
                strategy = Strategy.objects.get(id=strategyid)
                ServerTable.objects.filter(user=request.user, strategyname=strategy.strategyname).update(strategyname='自定义模版')
                Strategy.objects.filter(id=strategyid).delete()
        return HttpResponse("success")
    except:
        return HttpResponse("fail")


# 保存用户的Web防火墙url白名单设置
def saveurlwhitelist(request):
    logging.debug("saveurlwhitelist")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        urlwhitelistreq = json.loads(msg)

        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = urlwhitelistreq['ip']

        method = urlwhitelistreq['method']
        params = urlwhitelistreq['param']
        type = urlwhitelistreq['type']
        server = ServerTable.objects.get(serverip=ip)



        if 'modify' == type or 'add' == type:
            urls = params['url']
            for url in urls:
                urlwhitelist = UrlWhiteList.objects.filter(servername=server.servername, user=server.user, url=url)
                if not urlwhitelist:
                    UrlWhiteList.objects.create(servername=server.servername, user=server.user, url=url)
                    content = '添加URL白名单：%s' % (url)
                    addactionlog(server.user, server.servername, '网络防火墙', content)
        elif 'del' == type:
            for url in params:
                UrlWhiteList.objects.filter(servername=server.servername, user=server.user, url=url).delete()
                content = '删除URL白名单：%s' % (url)
                addactionlog(server.user, server.servername, '网络防火墙', content)
        return HttpResponse("success")
    else:
        serverid = request.GET['serverid']
        if serverid:
            servername = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategyname = Strategy.objects.get(user=request.user, id=strategyid)

        url = request.GET['url']
        remark = request.GET['remark']
        urlwhitelisrtid = request.GET['urlwhitelisrtid']

        # 判断要保存的网关IP和MAC绑定是否存在,存在更新、不存在新增
        if urlwhitelisrtid:
            UrlWhiteList.objects.get(id=urlwhitelisrtid).update(url=url, remark=remark)
        else:
            if serverid:
                UrlWhiteList.objects.create(servername=servername, user=request.user, url=url, remark=remark)
                content = '添加URL白名单：%s' % (url)
                addactionlog(servername.user, servername.servername, '网络防火墙', content)
            else:
                UrlWhiteList.objects.create(servername=strategyname, user=request.user, url=url, remark=remark)

        whitelists = UrlWhiteList.objects.filter(url=url)
        if whitelists:
            return HttpResponse("success")
        else:
            return HttpResponse("fail")

# 删除添加的用户的Web防火墙url白名单设置
def delurlwhitelistid(request):
    logging.debug("delurlwhitelistid")
    selecturlwhitelistid = request.GET['selecturlwhitelistid']
    try:
        selecturlwhitelistarry= selecturlwhitelistid.split(';')
        for urllisttid in selecturlwhitelistarry:
            if urllisttid:
                whitelists = UrlWhiteList.objects.filter(id=urllisttid)
                content = '删除URL白名单：%s' % (whitelists[0].url)
                addactionlog(whitelists[0].user, whitelists[0].servername, '网络防火墙', content)
                UrlWhiteList.objects.filter(id=urllisttid).delete()
        return HttpResponse("success")
    except:
        return HttpResponse("fail")


def OnARPfirewall(request,netfirewallobj):
    set = request.GET['set']

    # ARP防火墙网关和DNS设置模式
    if 'manu' in set:
        netfirewallobj.mode = 1
    elif 'auto' in set:
        netfirewallobj.mode = 0

    if 'InterceptExternalARPAttacks' in set:
        netfirewallobj.InterceptExternalARPAttacks = True
    else:
        netfirewallobj.InterceptExternalARPAttacks = False

    if 'InterceptLocalARPAttacks' in set:
        netfirewallobj.InterceptLocalARPAttacks = True
    else:
        netfirewallobj.InterceptLocalARPAttacks = False

    if 'InterceptIPConflict' in set:
        netfirewallobj.InterceptIPConflict = True
    else:
        netfirewallobj.InterceptIPConflict = False

    if 'LANStealth' in set:
        netfirewallobj.LANStealth = True
    else:
        netfirewallobj.LANStealth = False

    netfirewallobj.IP = request.GET['ip']
    netfirewallobj.MAC = request.GET['mac']
    netfirewallobj.GatewayIP = request.GET['gatewayip']
    netfirewallobj.GatewayMAC = request.GET['gatewaymac']

    netfirewallobj.save()

def OnWeb_firwall(request,netfirewallobj):
    WebFirewall_Seconds = request.GET['WebFirewall_Seconds']
    WebFirewall_Times = request.GET['WebFirewall_Times']
    WebFirewall_IPFreezeTime = request.GET['WebFirewall_IPFreezeTime']
    WebFirewall_IPAllowTime = request.GET['WebFirewall_IPAllowTime']
    WebFirewal_ProtPort = request.GET['WebFirewal_ProtPort']
    WebFirewal_VerifySessionOn = request.GET['WebFirewal_VerifySessionOn']
    WebFirewal_VerifySessionLevel = request.GET['WebFirewal_VerifySessionLevel']
    WebFirewal_AgentMaxIPs = request.GET['WebFirewal_AgentMaxIPs']
    WebFirewal_AgentTime = request.GET['WebFirewal_AgentTime']

    netfirewallobj.WebFirewall_Seconds = WebFirewall_Seconds
    netfirewallobj.WebFirewall_Times = WebFirewall_Times
    netfirewallobj.WebFirewall_IPFreezeTime = WebFirewall_IPFreezeTime
    netfirewallobj.WebFirewall_IPAllowTime = WebFirewall_IPAllowTime
    netfirewallobj.WebFirewal_ProtPort = WebFirewal_ProtPort
    netfirewallobj.WebFirewal_VerifySessionOn = WebFirewal_VerifySessionOn
    netfirewallobj.WebFirewal_VerifySessionLevel = WebFirewal_VerifySessionLevel
    netfirewallobj.WebFirewal_AgentMaxIPs = WebFirewal_AgentMaxIPs
    netfirewallobj.WebFirewal_AgentTime = WebFirewal_AgentTime

    netfirewallobj.save()
    
def OnDDosfirewall(request,netfirewallobj):
    SYNAttack_Seconds = request.GET['SYNAttack_Seconds']
    SYNAttack_times = request.GET['SYNAttack_times']
    ScanAttack_Seconds = request.GET['ScanAttack_Seconds']
    ScanAttack_times = request.GET['ScanAttack_times']
    FlowAttack_ICMP_Seconds = request.GET['FlowAttack_ICMP_Seconds']
    FlowAttack_ICMP_times = request.GET['FlowAttack_ICMP_times']
    FlowAttack_UDP_Seconds = request.GET['FlowAttack_UDP_Seconds']
    FlowAttack_UDP_times = request.GET['FlowAttack_UDP_times']
    DDoS_IPFreezeTime = request.GET['DDoS_IPFreezeTime']

    netfirewallobj.SYNAttack_Seconds = SYNAttack_Seconds
    netfirewallobj.SYNAttack_times = SYNAttack_times
    netfirewallobj.ScanAttack_Seconds = ScanAttack_Seconds
    netfirewallobj.ScanAttack_times = ScanAttack_times
    netfirewallobj.FlowAttack_ICMP_Seconds = FlowAttack_ICMP_Seconds
    netfirewallobj.FlowAttack_ICMP_times = FlowAttack_ICMP_times
    netfirewallobj.FlowAttack_UDP_Seconds = FlowAttack_UDP_Seconds
    netfirewallobj.FlowAttack_UDP_times = FlowAttack_UDP_times
    netfirewallobj.DDoS_IPFreezeTime = DDoS_IPFreezeTime

    netfirewallobj.save()

def OnFTPavoidviolence(request,netfirewallobj):
    FTP_Seconds = request.GET['FTP_Seconds']
    FTP_Times = request.GET['FTP_Times']
    FTP_IPFreezeTime = request.GET['FTP_IPFreezeTime']
    FTP_ProtPort = request.GET['FTP_ProtPort']

    netfirewallobj.FTP_Seconds = FTP_Seconds
    netfirewallobj.FTP_Times = FTP_Times
    netfirewallobj.FTP_IPFreezeTime = FTP_IPFreezeTime
    netfirewallobj.FTP_ProtPort = FTP_ProtPort

    netfirewallobj.save()
    
def OnRemoteDesktop(request,netfirewallobj):
    RemoteDesktop_Seconds = request.GET['RemoteDesktop_Seconds']
    RemoteDesktop_Times = request.GET['RemoteDesktop_Times']
    RemoteDesktop_IPFreezeTime = request.GET['RemoteDesktop_IPFreezeTime']

    netfirewallobj.RemoteDesktop_Seconds = RemoteDesktop_Seconds
    netfirewallobj.RemoteDesktop_Times = RemoteDesktop_Times
    netfirewallobj.RemoteDesktop_IPFreezeTime = RemoteDesktop_IPFreezeTime
    netfirewallobj.save()

def OnMySqlDB(request,netfirewallobj):
    MySqlDB_Seconds = request.GET['MySqlDB_Seconds']
    MySqlDB_Times = request.GET['MySqlDB_Times']
    MySqlDB_IPFreezeTime = request.GET['MySqlDB_IPFreezeTime']
    MySqlDB_ProtPort = request.GET['MySqlDB_ProtPort']

    netfirewallobj.MySqlDB_Seconds = MySqlDB_Seconds
    netfirewallobj.MySqlDB_Times = MySqlDB_Times
    netfirewallobj.MySqlDB_IPFreezeTime = MySqlDB_IPFreezeTime
    netfirewallobj.MySqlDB_ProtPort = MySqlDB_ProtPort

    netfirewallobj.save()


def OnMSSQLDB(request,netfirewallobj):
    MSSQLDB_Seconds = request.GET['MSSQLDB_Seconds']
    MSSQLDB_Times = request.GET['MSSQLDB_Times']
    MSSqlDB_IPFreezeTime = request.GET['MSSQLDB_IPFreezeTime']

    netfirewallobj.MSSqlDB_Seconds = MSSQLDB_Seconds
    netfirewallobj.MSSqlDB_Times = MSSQLDB_Times
    netfirewallobj.MSSqlDB_IPFreezeTime = MSSqlDB_IPFreezeTime

    netfirewallobj.save()

def OnARPfirewallReSet(netfirewallobj):
    netfirewallobj.InterceptExternalARPAttacks = True
    netfirewallobj.InterceptLocalARPAttacks = False
    netfirewallobj.InterceptIPConflict = False
    netfirewallobj.LANStealth = False
    netfirewallobj.mode = 0
    netfirewallobj.save()

def OnDDosfirewallReSet(netfirewallobj):
    netfirewallobj.SYNAttack_Seconds = 10
    netfirewallobj.SYNAttack_times = 200
    netfirewallobj.ScanAttack_Seconds = 10
    netfirewallobj.ScanAttack_times = 50
    netfirewallobj.FlowAttack_ICMP_Seconds = 10
    netfirewallobj.FlowAttack_ICMP_times = 500
    netfirewallobj.FlowAttack_UDP_Seconds = 10
    netfirewallobj.FlowAttack_UDP_times = 2000
    netfirewallobj.DDoS_IPFreezeTime = 10
    netfirewallobj.save()

def OnWeb_firwallReSet(netfirewallobj):
    netfirewallobj.WebFirewall_Seconds = 10
    netfirewallobj.WebFirewall_Times = 300
    netfirewallobj.WebFirewall_IPFreezeTime = 10
    netfirewallobj.WebFirewall_IPAllowTime = 10
    netfirewallobj.WebFirewal_ProtPort = 80
    netfirewallobj.WebFirewal_VerifySessionOn = False
    netfirewallobj.WebFirewal_VerifySessionLevel = 0
    netfirewallobj.WebFirewal_AgentMaxIPs = 30
    netfirewallobj.WebFirewal_AgentTime = 30
    netfirewallobj.save()

def OnFTPavoidviolenceReset(netfirewallobj):
    netfirewallobj.FTP_Seconds =60
    netfirewallobj.FTP_Times = 10
    netfirewallobj.FTP_IPFreezeTime = 10
    netfirewallobj.FTP_ProtPort = 21
    netfirewallobj.save()

def OnRemoteDesktopReset(netfirewallobj):
    netfirewallobj.RemoteDesktop_Seconds =60
    netfirewallobj.RemoteDesktop_Times = 10
    netfirewallobj.RemoteDesktop_IPFreezeTime = 10
    netfirewallobj.save()

def OnMySqlDBReset(netfirewallobj):
    netfirewallobj.MySqlDB_Seconds = 60
    netfirewallobj.MySqlDB_Times =10
    netfirewallobj.MySqlDB_IPFreezeTime = 10
    netfirewallobj.MySqlDB_ProtPort = 3306
    netfirewallobj.save()

def OnMSSQLDBReset(netfirewallobj):
    netfirewallobj.MSSqlDB_Seconds = 60
    netfirewallobj.MSSqlDB_Times =10
    netfirewallobj.MSSqlDB_IPFreezeTime = 10
    netfirewallobj.save()

# 恢复用户的网络防火墙设置到默认状态
def resetnetfirewall(request):
    logging.debug("resetnetfirewall")
    serverid = request.GET['serverid']
    if serverid:
        server = ServerTable.objects.get(user=request.user, id=serverid)
    else:
        strategyid = request.GET['strategyid']
        strategyname = Strategy.objects.get(user=request.user, id=strategyid)

    obj = request.GET['obj']
    try:
        if serverid:
            netfirewall = NetFirewall.objects.get(servername=server.servername)
        else:
            netfirewall = NetFirewall.objects.get(servername=strategyname)
        if 'ARPfirwall' == obj:
            OnARPfirewallReSet(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复ARP防火墙的默认设置')
        if 'DDosfirwall' == obj:
            OnDDosfirewallReSet(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复DDoS防火墙的默认设置')
        if 'Web_firwall' == obj:
            OnWeb_firwallReSet(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复Web防火墙的默认设置')
        if 'FTP_avoidviolence' == obj:
            OnFTPavoidviolenceReset(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复FTP防暴力破解的默认设置')
        if 'RemoteDesktop' == obj:
            OnRemoteDesktopReset(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复远程桌面防暴力破解的默认设置')
        if 'MySqlDB' == obj:
            OnMySqlDBReset(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复MSSQL防暴力破解的默认设置')
        if 'MSSQLDB' == obj:
            OnMSSQLDBReset(netfirewall)
            addactionlog(server.user, server.servername, '网络防火墙', '恢复MSSQL防暴力破解的默认设置')
        return HttpResponse("success")
    except:
        return HttpResponse("fail")

# ARP防火墙设置同步
def saveArpFireWall(request):
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        arpfirewallreq = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = GetRequestIP['ip']

        method = arpfirewallreq['method']
        params = arpfirewallreq['param']
        server = ServerTable.objects.get(serverip=ip)
        mode = arpfirewallreq['mode']

        logging.debug("ARPFireWall")

        try:
            if 'auto' == mode:
                arpmode = 0
                logging.debug('auto')
            elif 'manu' == mode:
                arpmode = 1
                logging.debug('manu')

            m_LocalArp = params['m_LocalArp']
            m_Ipconflict = params['m_Ipconflict']
            m_LanSteal = params['m_LanSteal']

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(InterceptLocalARPAttacks=m_LocalArp,InterceptIPConflict=m_Ipconflict,LANStealth=m_LanSteal,mode=arpmode)
            addactionlog(server.user, server.servername, '网络防火墙', '修改ARP防火墙设置')
            return HttpResponse("success")
        except:
            return HttpResponse("fail")


# 保存用户的网络防火墙设置
def savenetfirewall(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        netfirewallreq = json.loads(msg)

        ip = GetRequestIP(request)

        if ip == '127.0.0.1':
            ip = netfirewallreq['ip']

        method = netfirewallreq['method']
        params = netfirewallreq['param']
        type = netfirewallreq['type']
        server = ServerTable.objects.get(serverip=ip)

        if 'openall' == type:
            addactionlog(server.user, server.servername, '网络防火墙', '一键开启')

        mode = ''
        submode = ''
        status = False
        # 网络防火墙主界面设置
        if 'netfirewallmaincfig' == method:
            if 'ARPFireWall' in params:
                server.ARPfirwall = params['ARPFireWall']
                status = params['ARPFireWall']
                mode = '网络防火墙'
                submode = 'ARP防火墙'
            if 'BlakcList' in params:
                server.super_blacklist = params['BlakcList']
                status = params['BlakcList']
                mode = '超级黑名单'
                submode = '超级黑名单'
            if 'DDosFireWall' in params:
                server.DDosfirwall = params['DDosFireWall']
                status = params['DDosFireWall']
                mode = '网络防火墙'
                submode = 'DDoS防火墙'
            if 'FTPProtect' in params:
                server.FTP_avoidviolence = params['FTPProtect']
                status = params['FTPProtect']
                mode = '网络防火墙'
                submode = 'FTP防暴力破解'
            if 'ForbidPing' in params:
                server.forbid_ping = params['ForbidPing']
                status = params['ForbidPing']
                mode = '端口保护'
                submode = '禁止ping本机'
            if 'MSSQLProtect' in params:
                server.MSSQL_avoidviolence = params['MSSQLProtect']
                status = params['MSSQLProtect']
                mode = '网络防火墙'
                submode = 'MSSQL防暴力破解'
            if 'MySQLProtect' in params:
                server.MySQL_avoidviolence = params['MySQLProtect']
                status = params['MySQLProtect']
                mode = '网络防火墙'
                submode = 'MySQL防暴力破解'
            if 'PortPolicy' in params:
                server.port_security = params['PortPolicy']
                status = params['PortPolicy']
                mode = '端口保护'
                submode = '端口安全策略'
            if 'RemoteProtect' in params:
                server.ReDesktop_avoidviolence = params['RemoteProtect']
                status = params['RemoteProtect']
                mode = '网络防火墙'
                submode = '远程桌面防暴力破解'
            if 'WebFireWall' in params:
                server.Web_firwall = params['WebFireWall']
                status = params['WebFireWall']
                mode = '网络防火墙'
                submode = 'Web防火墙'
            if 'WhiteList' in params:
                server.super_whitelist = params['WhiteList']
                status = params['WhiteList']
                mode = '超级白名单'
                submode = '超级白名单'
            server.save()
            content = '功能：%s 修改状态为：%s' % (submode, status)

            if 'openall' != type:
                addactionlog(server.user, server.servername, mode, content)
            return HttpResponse("success")
        elif 'DDosFireWall' == method:
            SYNAttack_Seconds = int(params['nSynSec'])
            SYNAttack_times = int(params['nSynConut'])
            ScanAttack_Seconds = int(params['nScanSec'])
            ScanAttack_times = int(params['nScanConut'])
            FlowAttack_ICMP_Seconds = int(params['nStreamICMPSec'])
            FlowAttack_ICMP_times = int(params['nStreamICMPSConut'])
            FlowAttack_UDP_Seconds = int(params['nStreamUDPSec'])
            FlowAttack_UDP_times = int(params['nStreamUDPSConut'])
            DDoS_IPFreezeTime = int(params['nFrostMin'])

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(SYNAttack_Seconds=SYNAttack_Seconds, SYNAttack_times=SYNAttack_times, ScanAttack_Seconds=ScanAttack_Seconds,ScanAttack_times=ScanAttack_times,FlowAttack_ICMP_Seconds=FlowAttack_ICMP_Seconds,FlowAttack_ICMP_times=FlowAttack_ICMP_times,FlowAttack_UDP_Seconds=FlowAttack_UDP_Seconds,FlowAttack_UDP_times=FlowAttack_UDP_times,DDoS_IPFreezeTime=DDoS_IPFreezeTime)

            addactionlog(server.user, server.servername, '网络防火墙', '修改DDoS防火墙设置')
        elif 'FTPProtect'   == method:
            FTP_Seconds = int(params['nSec'])
            FTP_Times = int(params['nConut'])
            FTP_IPFreezeTime = int(params['nFrostMin'])
            FTP_ProtPort = params['nProt']

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(FTP_Seconds=FTP_Seconds, FTP_Times=FTP_Times,FTP_IPFreezeTime=FTP_IPFreezeTime,FTP_ProtPort=FTP_ProtPort)
            addactionlog(server.user, server.servername, '网络防火墙', '修改FTP防暴力破解设置')
        elif 'MSSQLProtect' == method:
            MSSqlDB_Seconds = int(params['nSec'])
            MSSqlDB_Times = int(params['nConut'])
            MSSqlDB_IPFreezeTime = params['nFrostMin']


            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(MSSqlDB_Seconds=MSSqlDB_Seconds,MSSqlDB_Times=MSSqlDB_Times,MSSqlDB_IPFreezeTime=MSSqlDB_IPFreezeTime)
            addactionlog(server.user, server.servername, '网络防火墙', '修改MSSQL防暴力破解设置')
        elif 'MySQLProtect' == method:
            MySqlDB_Seconds = int(params['nSec'])
            MySqlDB_Times = int(params['nConut'])
            MySqlDB_IPFreezeTime = int(params['nFrostMin'])
            MySqlDB_ProtPort = params['nProt']

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(MySqlDB_Seconds=MySqlDB_Seconds,MySqlDB_Times=MySqlDB_Times,MySqlDB_IPFreezeTime=MySqlDB_IPFreezeTime,MySqlDB_ProtPort=MySqlDB_ProtPort)
            addactionlog(server.user, server.servername, '网络防火墙', '修改MySQL防暴力破解设置')
        elif 'RemoteProtect' == method:
            RemoteDesktop_Seconds = int(params['nSec'])
            RemoteDesktop_Times = int(params['nConut'])
            RemoteDesktop_IPFreezeTime = int(params['nFrostMin'])

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(RemoteDesktop_Seconds=RemoteDesktop_Seconds, RemoteDesktop_Times=RemoteDesktop_Times, RemoteDesktop_IPFreezeTime=RemoteDesktop_IPFreezeTime)
            addactionlog(server.user, server.servername, '网络防火墙', '修改远程桌面防暴力破解设置')
        elif 'WebFireWall' == method:
            Prots = params['nProt']
            ProtPort = ''
            for port in Prots:
                ProtPort += str(port) + ';'

            WebFirewall_Seconds = int(params['nSec'])
            WebFirewall_Times = int(params['nConut'])
            WebFirewall_IPFreezeTime = int(params['nFrostMin'])
            WebFirewal_ProtPort = ProtPort
            # WebFirewal_VerifySessionLevel = int(params['nModuleType'])
            WebFirewal_AgentMaxIPs = int(params['nProxyIPNums'])
            WebFirewal_AgentTime = int(params['nProxyTimes'])

            NetFirewall.objects.filter(user=server.user, servername=server.servername).update(WebFirewall_Seconds=WebFirewall_Seconds, WebFirewall_Times=WebFirewall_Times,WebFirewall_IPFreezeTime=WebFirewall_IPFreezeTime,WebFirewal_ProtPort=ProtPort,WebFirewal_AgentMaxIPs=WebFirewal_AgentMaxIPs,WebFirewal_AgentTime=WebFirewal_AgentTime,)
            addactionlog(server.user, server.servername, '网络防火墙', '修改Web防火墙设置')
        return HttpResponse("success")

    else:
        serverid = request.GET['serverid']
        if serverid:
            server = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategyname = Strategy.objects.get(user=request.user, id=strategyid)

        obj = request.GET['obj']

        try:
            if serverid:
                netfirewall = NetFirewall.objects.get(servername=server.servername)
            else:
                netfirewall = NetFirewall.objects.get(servername=strategyname)
            if 'ARPfirwall' == obj:
                OnARPfirewall(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改ARP防火墙的设置')
            if 'DDosfirwall' == obj:
                OnDDosfirewall(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改DDoS防火墙的设置')
            if 'Web_firwall' == obj:
                OnWeb_firwall(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改Web防火墙的设置')
            if 'FTP_avoidviolence' == obj:
                OnFTPavoidviolence(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改FTP防暴力破解的设置')
            if 'RemoteDesktop' == obj:
                OnRemoteDesktop(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改远程桌面防暴力破解的设置')
            if 'MySqlDB' == obj:
                OnMySqlDB(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改MySQL防暴力破解的设置')
            if 'MSSQLDB' == obj:
                OnMSSQLDB(request, netfirewall)
                addactionlog(server.user, server.servername, '网络防火墙', '修改MSSQL防暴力破解的设置')

            return HttpResponse("success")
        except:
            return HttpResponse("fail")


# 添加的自定义网关IP和MAC绑定对
def savecustomgateway(request):
    logging.debug("savecustomgateway")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        gatewayreq = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = gatewayreq['ip']

        method = gatewayreq['method']
        params = gatewayreq['param']
        server = ServerTable.objects.get(serverip=ip)
        netfirewall = NetFirewall.objects.get(servername=server.servername,user=server.user)

        # try:
        ServerGateway.objects.filter(servername=server.servername, user=server.user).delete()
        for param in params:
            if 'manu' == param['type']:
                IP = params['LocalIp']
                MAC = params['LocalMac']
                GatewayIP = params['GatewayIp']
                GatewayMAC = params['GatewayMac']

                NetFirewall.objects.filter(servername=server.servername, user=server.user).update(IP=IP,MAC=MAC,GatewayIP=GatewayIP,GatewayMAC=GatewayMAC)
                content = '修改了ARP防火墙手动网关及DNS设置：本地IP地址：%s，本地MAC地址：%s，网关IP地址：%s，网关MAC地址：%s' % (IP, MAC, GatewayIP, GatewayMAC)
                addactionlog(server.user, server.servername, '网络防火墙', content)
            elif 'auto' == param['type']:
                IP = param['LocalIp']
                MAC = param['LocalMac']
                GatewayIP = param['GatewayIp']
                GatewayMAC = param['GatewayMac']
                connectname =    param['ConnectName']

                ServerGateway.objects.create(servername=server.servername, user=server.user,IP=IP, MAC=MAC,gatewayip=GatewayIP,gatewaymac=GatewayMAC,connectname=connectname)
                # NetFirewall.objects.filter(servername=server.servername, user=server.user).update(Auto_IP=Auto_IPAuto_MAC=Auto_MAC,Auto_GatewayIP=Auto_GatewayIP,Auto_GatewayMAC=Auto_GatewayMAC)

        return HttpResponse("success")
        # except:
        #     return HttpResponse("fail")

    else:
        serverid = request.GET['serverid']

        if serverid:
            server = ServerTable.objects.get(user=request.user, id=serverid)
            netfirewall = NetFirewall.objects.get(servername=server.servername,user=server.user)
        else:
            strategyid = request.GET['strategyid']
            strategy = Strategy.objects.get(user=request.user, id=strategyid)
            netfirewall = NetFirewall.objects.get(servername=strategy.strategyname,user=strategy.user)

        netfirewall.IP = request.GET['ip']
        netfirewall.MAC = request.GET['mac']
        netfirewall.GatewayIP = request.GET['gatewayip']
        netfirewall.GatewayMAC = request.GET['gatewaymac']
        netfirewall.save()

        content = '修改了ARP防火墙手动网关及DNS设置：本地IP地址：%s，本地MAC地址：%s，网关IP地址：%s，网关MAC地址：%s' % (request.GET['ip'], request.GET['mac'], request.GET['gatewayip'], request.GET['gatewaymac'])
        addactionlog(server.user, server.servername, '网络防火墙', content)

        return HttpResponse("success")


# 删除勾选自定义网关IP和MAC绑定对
def delcustomgateway(request):
    # logging.debug("delcustomgateway")
    # selectgatewayid = request.GET['selectgatewayid']
    # try:
    #     selectgatewayidarry = selectgatewayid.split(';')
    #     for gatewayid in selectgatewayidarry:
    #         if gatewayid:
    #             CustomizeGateway.objects.filter(id=gatewayid).delete()
    #     return HttpResponse("success")
    # except:
    #     return HttpResponse("fail")
    return HttpResponse("success")


# 获取协议类型
def protocolmodel(index):
    return {
            '0': "TCP",
            '1': "UDP",
            '2': "ICMP",
            '3': "IGMP",
            '4': "IP",
            '5': "RDP",
            '6': "ALL",
    }.get(index,'error')    #'error'为默认返回值，可自设置

# 获取规则类型
def rulemodel(index):
    return {
            '0': "false",
            '1': "true",
    }.get(index,'error')    #'error'为默认返回值，可自设置

# 获取生效时间单位类型
def datemodel(index):
    return {
            '0': "分钟",
            '1': "时",
            '2': "天",
    }.get(index,'error')    #'error'为默认返回值，可自设置

# 保存添加的端口安全策略
def addportsecurity(request):
    logging.debug("addportsecurity")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        addportreq = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = addportreq['ip']

        method = addportreq['method']
        params = addportreq['param']
        type = addportreq['type']
        server = ServerTable.objects.get(serverip=ip)

        for param in params:
            port = param['PortNum']
            protocoltype = param['Protocol']
            oldprotocol = param['oldProtocol']
            ruletype = param['Strategies']
            ipsegments = param['segmentIp']
            singleips = param['signalIp']
            exception = ''
            for singleip in singleips:
                exception += singleip + ';'

            if oldprotocol:
                portsecurities = PortSecurity.objects.filter(servername=server,user=server.user,port=port,protocol=oldprotocol)
            else:
                portsecurities = PortSecurity.objects.filter(servername=server, user=server.user, port=port, protocol=protocoltype)
            # 端口安全策略表，存在这张表，修改
            if portsecurities:
                if oldprotocol:
                    PortSecurity.objects.filter(servername=server, user=server.user, port=port,protocol=oldprotocol).update(port=port,protocol=protocoltype,rule=ruletype,exception=exception)
                    PortIpSegment.objects.filter(servername=server, user=server.user, port=port, protocol=oldprotocol).delete()
                    for ipsegment in ipsegments:
                        if '' != ipsegment:
                            startip = ipsegment.split('-')[0]
                            endip = ipsegment.split('-')[1]
                            if '' != startip and '' != endip:
                                PortIpSegment.objects.create(servername=server.servername, user=server.user, port=port,startip=startip, endip=endip, protocol=protocoltype)

                else:
                    PortSecurity.objects.filter(servername=server, user=server.user, port=port,protocol=protocoltype).update(port=port,rule=ruletype,exception=exception)
                    PortIpSegment.objects.filter(servername=server, user=server.user, port=port, protocol=protocoltype).delete()
                    for ipsegment in ipsegments:
                        if '' != ipsegment:
                            startip = ipsegment.split('-')[0]
                            endip = ipsegment.split('-')[1]
                            if '' != startip and '' != endip:
                                PortIpSegment.objects.create(servername=server.servername, user=server.user, port=port,
                                                             startip=startip, endip=endip, protocol=protocoltype)
                content = '修改端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype,ruletype,exception)
                addactionlog(server.user, server.servername, '端口保护', content)
            else:
                PortSecurity.objects.create(servername=server, user=server.user, port=port,protocol=protocoltype,rule=ruletype,exception=exception)
                content = '添加端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype, ruletype, exception)
                addactionlog(server.user, server.servername, '端口保护', content)
                for ipsegment in ipsegments:
                    if '' != ipsegment:
                        startip = ipsegment.split('-')[0]
                        endip = ipsegment.split('-')[1]
                        if '' != startip and '' != endip:
                            PortIpSegment.objects.create(servername=server.servername, user=server.user, port=port, startip=startip,endip=endip,protocol=protocoltype)
        return HttpResponse("success")
    else:
        serverid = request.GET['serverid']
        if serverid:
            server = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategy = Strategy.objects.get(user=request.user, id=strategyid)

        port = request.GET['port']
        portid = request.GET['portid']
        protocoltypeindex = request.GET['protocoltype']
        ruleindex = request.GET['ruletype']    
        singleip = request.GET['singleip']
        ipsegment = request.GET['ipsegment']
        protocoltype = protocolmodel(protocoltypeindex)
        ruletype = rulemodel(ruleindex)
        ipsegmentarray = ipsegment.split(';')

        # 判断要保存的端口是否存在,存在更新、不存在新增---修改
        if portid:
            portsecurity = PortSecurity.objects.get(id=portid)
            PortSecurity.objects.filter(id=portid).update(port=port,protocol=protocoltype,rule=ruletype,exception=singleip)
            content = '修改端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype, ruletype, singleip)
            addactionlog(server.user, server.servername, '端口保护', content)
            PortIpSegment.objects.filter(servername=portsecurity.servername,user=portsecurity.user, port=port,protocol=protocoltype).delete()
            for ipsegment in ipsegmentarray:
                if '' != ipsegment:
                    startip = ipsegment.split(':')[0]
                    endip = ipsegment.split(':')[1]
                    if '' != startip and '' != endip:
                        PortIpSegment.objects.create(servername=portsecurity.servername,user=portsecurity.user, port=portsecurity.port,startip=startip,endip=endip,protocol=protocoltype)
        else:
            # 添加端口安全策略
            if serverid:
                ports = PortSecurity.objects.filter(servername=server,user=server.user,port=port)
                # 判断端口存不存在
                if ports:
                    # 端口存在，判断端口的协议是不是不为ALL并且端口号是不是不为0
                    if 0 == port or 'ALL' == protocoltype:
                        return HttpResponse("fail")

                    for port in ports:
                        if protocoltype == port.protocol or 'ALL' == port.protocol:
                            return HttpResponse("fail")

                    PortSecurity.objects.create(servername=server,user=server.user,port=port,protocol=protocoltype,rule=ruletype,exception=singleip)
                    content = '添加端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype, ruletype, singleip)
                    addactionlog(server.user, server.servername, '端口保护', content)
                    for ipsegment in ipsegmentarray:
                        if '' != ipsegment:
                            startip = ipsegment.split(':')[0]
                            endip = ipsegment.split(':')[1]
                            if '' != startip and '' !=endip:
                                PortIpSegment.objects.create(servername=server.servername, user=server.user,port=port, startip=startip,endip=endip,protocol=protocoltype)
                else:
                    # 端口不存在
                    PortSecurity.objects.create(servername=server, user=server.user, port=port, protocol=protocoltype,rule=ruletype, exception=singleip)
                    content = '添加端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype, ruletype, singleip)
                    addactionlog(server.user, server.servername, '端口保护', content)
                    for ipsegment in ipsegmentarray:
                        if '' != ipsegment:
                            startip = ipsegment.split(':')[0]
                            endip = ipsegment.split(':')[1]
                            if '' != startip and '' != endip:
                                PortIpSegment.objects.create(servername=server.servername, user=server.user, port=port,startip=startip, endip=endip,protocol=protocoltype)
            else:
                PortSecurity.objects.create(servername=strategy, user=strategy.user, port=port, protocol=protocoltype,rule=ruletype, exception=singleip)
                content = '添加端口安全策略：端口号：%s，端口协议：%s，规则：%s，例外：%s' % (port, protocoltype, ruletype, singleip)
                addactionlog(server.user, server.servername, '端口保护', content)
                for ipsegment in ipsegmentarray:
                    startip = ipsegment.split(':')[0]
                    endip = ipsegment.split(':')[1]
                    if '' != startip and '' != endip:
                        PortIpSegment.objects.create(servername=strategy, user=strategy.user,port=port, startip=startip, endip=endip)

        portsecurities = PortSecurity.objects.filter(port=port)
        if portsecurities:
            return HttpResponse("success")
        else:
            return HttpResponse("fail")

# 获取指定服务器的网络流量统计
def getnetcount(request):
    servername = request.GET['server']
    server = ServerTable.objects.get(servername=servername);
    return HttpResponse(server.networkUpFlow + '&' + server.networkDownFlow)

# 删除勾选的端口安全策略
def delport(request):
    logging.debug("delport")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']


        method = req['method']
        params = req['param']
        server = ServerTable.objects.get(serverip=ip)
        for param in params:
            port = param['PortNum']
            protocoltype = param['Protocol']
            portdis = PortSecurity.objects.filter(servername=server, user=server.user, port=port, protocol=protocoltype)
            content = '删除端口安全策略：端口号：%s' % (portdis[0].port)
            addactionlog(portdis[0].user, portdis[0].servername, '端口保护', content)
            PortSecurity.objects.filter(servername=server, user=server.user, port=port, protocol=protocoltype).delete()
            PortIpSegment.objects.filter(servername=server, user=server.user, port=port, protocol=protocoltype).delete()
        return HttpResponse("success")
    else:
        selectportid = request.GET['selectportid']
        try:
            selectportidarray= selectportid.split(';')
            for portid in selectportidarray:
                if portid:
                    port = PortSecurity.objects.get(id = portid)
                    content = '删除端口安全策略：端口号：%s' % (port.port)
                    addactionlog(port.user, port.servername, '端口保护', content)
                    PortIpSegment.objects.filter(port=port.port,protocol=port.protocol).delete()
                    PortSecurity.objects.filter(id=portid).delete()
            return HttpResponse("success")
        except:
            return HttpResponse("fail")

# 保存端口安全策略的防护策略
def portsecuritysolution(request):
    logging.debug("portsecuritysolution")
    serverid = request.GET['serverid']
    if serverid:
        servername = ServerTable.objects.get(user=request.user, id=serverid)
    else:
        strategyid = request.GET['strategyid']
        strategyname = Strategy.objects.get(user=request.user, id=strategyid)

    portid = request.GET['portid']
    obj = request.GET['obj']

    port = PortSecurity.objects.get(id=portid)
    if port:
        if obj == 'stop':
            if port.solution_stop:
                port.solution_stop = False
            else:
                port.solution_stop = True
        if obj == 'record':
            if port.solution_record:
                port.solution_record = False
            else:
                port.solution_record = True

    port.save()

    return HttpResponse('success')

# def fileprotmodel(index):
#     return {
#             '0': "允许文件",
#             '1': "阻止文件",
#             '2': "允许扩展名",
#             '3': "阻止扩展名",
#             '4': "进程白名单",
#             '5': "进程黑名单",
#     }.get(index,'error')    #'error'为默认返回值，可自设置
#
# def registryprotmodel(index):
#     return {
#             '0': "进程白名单",
#             '1': "进程黑名单",
#     }.get(index,'error')    #'error'为默认返回值，可自设置

# 保存外围控制的策略
def outsidecontrolsolution(request):
    logging.debug("outsidecontrolsolution")
    serverid = request.GET['serverid']
    serverinfo = ServerTable.objects.filter(user=request.user, id=serverid)
    servername = serverinfo[0].servername;

    device_id = request.GET['device_id']
    obj = request.GET['obj']

    device = OutsideDevice.objects.get(id=device_id)
    if device:
        if obj == 'stop':
            if device.solution_stop:
                device.solution_stop = False
            else:
                device.solution_stop = True
        if obj == 'record':
            if device.solution_record:
                device.solution_record = False
            else:
                device.solution_record = True

    device.save()

    return HttpResponse('success')

# 保存应用程序控制的策略
def appcontrolsolution(request):
    logging.debug("appcontrolsolution")
    serverid = request.GET['serverid']
    serverinfo = ServerTable.objects.filter(user=request.user, id=serverid)
    servername = serverinfo[0].servername;

    app_id = request.GET['app_id']
    obj = request.GET['obj']

    app = AppControl.objects.get(id=app_id)
    if app:
        if obj == 'stop':
            if app.solution_stop:
                app.solution_stop = False
            else:
                app.solution_stop = True
        if obj == 'record':
            if app.solution_record:
                app.solution_record = False
            else:
                app.solution_record = True

        app.save()

    return HttpResponse('success')

# 保存超级黑白名单
def savesuperlist(request):
    logging.debug("savesuperlist")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        superlistreq = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = superlistreq['ip']

        params = []
        method = superlistreq['method']
        params = superlistreq['param']
        server = ServerTable.objects.get(serverip=ip)
        type = superlistreq['type']
        mode = ''

        if 'BlackList' == method:
            listtype = 'SUPER_BLACKLIST'
            mode = '超级黑名单'
        elif 'WhiteList' == method:
            listtype = 'SUPER_WHITELIST'
            mode = '超级白名单'

        for param in params:
            segmentIp = param['segmentIp']
            Note = param['Note']
            signalIp = param['signalIp']
            oldIP = param['oldIp']
            if segmentIp:
                startip = segmentIp.split('-')[0]
                endip = segmentIp.split('-')[1]

                if '' != oldIP:
                    oldstartip = oldIP.split('-')[0]
                    oldendip = oldIP.split('-')[1]
                    superlists = SuperList.objects.filter(servername=server, user=server.user, listtype=listtype, startip=oldstartip, endip=oldendip)
                else:
                    superlists = SuperList.objects.filter(servername=server, user=server.user, listtype=listtype,startip=startip, endip=endip)

                if superlists:
                    SuperList.objects.filter(servername=server, user=server.user, listtype=listtype, startip=oldstartip, endip=oldendip).update(startip=startip, endip=endip, ipsremark=Note)
                    content = '修改%s：起始IP：%s，结尾IP：%s，备注：%s' % (mode,startip, endip, Note)
                    addactionlog(server.user, server.servername, mode, content)
                else:
                    SuperList.objects.create(servername=server, user=server.user, listtype=listtype, startip=startip, endip=endip, ipsremark=Note)
                    content = '添加%s：起始IP：%s，结尾IP：%s，备注：%s' % (mode,startip, endip, Note)
                    addactionlog(server.user, server.servername, mode, content)

            elif signalIp:
                if '' != oldIP:
                    superlists = SuperList.objects.filter(servername=server, user=server.user, listtype=listtype,addr=oldIP)
                else:
                    superlists =  SuperList.objects.filter(servername=server, user=server.user, listtype=listtype,addr=signalIp)

                if superlists:
                    SuperList.objects.filter(servername=server, user=server.user, listtype=listtype, addr=oldIP).update(addr=signalIp,ipremark=Note)
                    content = '修改%s：IP：%s，备注：%s' % (mode, signalIp, Note)
                    addactionlog(server.user, server.servername, mode, content)
                else:
                    SuperList.objects.create(servername=server, user=server.user, listtype=listtype, addr=signalIp, ipremark=Note)
                    content = '添加%s：IP：%s，备注：%s'% (mode, signalIp, Note)
                    addactionlog(server.user, server.servername, mode, content)

        return HttpResponse("success")
    else:
        serverid = request.GET['serverid']
        if serverid:
            server = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategy = Strategy.objects.get(user=request.user, id=strategyid)

        try:
            newaddr = request.GET['addr']
            listtype = request.GET['listtype']
            superlistid = request.GET['superlistid']
            ipremark = request.GET['ipremark']
            startip = request.GET['startip']
            endip = request.GET['endip']
            ipsremark = request.GET['ipsremark']
            iptype = request.GET['iptype']

            if 'SUPER_WHITELIST' == listtype:
                mode = '超级白名单'
            elif 'SUPER_BLACKLIST' == listtype:
                mode = '超级黑名单'

            # 判断要保存的白名单是否存在,存在更新、不存在新增
            if superlistid:
                superlist = SuperList.objects.get(id=superlistid)
                addr = superlist.addr
                SuperList.objects.filter(id=superlistid).update(addr=newaddr,ipremark=ipremark,startip=startip,endip=endip,ipsremark=ipsremark)
                content = '修改%s：单独IP：%s，起始IP：%s，结尾IP：%s，备注：%s' % (mode, newaddr, startip, endip, ipsremark)
                addactionlog(server.user, server.servername, mode, content)
            else:
                if serverid:
                    if 'ipsegment' == iptype:
                        SuperList.objects.create(servername=server.servername, user=server.user, listtype=listtype,startip=startip,endip=endip,ipsremark=ipsremark)
                        content = '添加%s：起始IP：%s，结尾IP：%s，备注：%s' % (mode, startip, endip, ipsremark)
                        addactionlog(server.user, server.servername, mode, content)
                    else:
                        SuperList.objects.create(servername=server.servername, user=server.user, addr=newaddr,ipremark=ipremark, listtype=listtype)
                        content = '添加%s：IP：%s，备注：%s' % (mode, newaddr, ipremark)
                        addactionlog(server.user, server.servername, mode, content)
                else:
                    if 'ipsegment' == iptype:
                        SuperList.objects.create(servername=strategy.strategyname, user=strategy.user, listtype=listtype,startip=startip, endip=endip, ipsremark=ipsremark)
                    else:
                        SuperList.objects.create(servername=strategy.strategyname, user=strategy.user, addr=newaddr,ipremark=ipremark, listtype=listtype)

            return HttpResponse("success")
        except:
            return HttpResponse("fail")

# 删除添加的超级黑白名单
def delsuperlist(request):
    logging.debug("delsuperlist")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        server = ServerTable.objects.get(serverip=ip)

        if 'BlackList' == method:
            listtype = 'SUPER_BLACKLIST'
            mode = '超级黑名单'
        elif 'WhiteList' == method:
            listtype = 'SUPER_WHITELIST'
            mode = '超级白名单'

        for param in params:
            if '-' in param:
                startip = param.split('-')[0]
                endip = param.split('-')[1]
                SuperList.objects.filter(servername=server, user=server.user, listtype=listtype, startip=startip, endip=endip).delete()
                content = '删除%s：起始IP：%s，结尾IP：%s' % (mode, startip, endip)
                addactionlog(server.user, server.servername, mode, content)
            else:
                SuperList.objects.filter(servername=server, user=server.user, listtype=listtype, addr=param).delete()
                content = '删除%s：IP：%s' % (mode, param)
                addactionlog(server.user, server.servername, mode, content)
        return HttpResponse("success")
    else:
        selectsuperlisttid = request.GET['selectsuperlisttid']
        try:
            selectwhitelistidarry= selectsuperlisttid.split(';')
            for superlisttid in selectwhitelistidarry:
                if superlisttid:
                    superlist =  SuperList.objects.filter(id=superlisttid)[0]
                    mode = ''
                    if 'SUPER_WHITELIST' == superlist.listtype:
                        mode = '超级白名单'
                    elif 'SUPER_BLACKLIST' == superlist.listtype:
                        mode = '超级黑名单'

                    if superlist.startip:
                        content = '删除%s：起始IP：%s，结尾IP：%s' % (mode, superlist.startip, superlist.endip)
                        addactionlog(superlist.user, superlist.servername, mode, content)
                    else:
                        content = '删除%s：IP：%s' % (mode, superlist.addr)
                        addactionlog(superlist.user, superlist.servername, mode, content)

                    SuperList.objects.filter(id=superlisttid).delete()
            return HttpResponse("success")
        except:
            return HttpResponse("fail")

# 保存认证的白名单
def savewhitelist(request):
    logging.debug("savewhitelist")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        type = req['type']
        server = ServerTable.objects.get(serverip=ip)

        for param in params:
            ID = param['Id']
            if (0 == param['Type']):
                authmethod = 'COMPUTER_IP'
            elif (1 == param['Type']):
                authmethod = 'COMPUTER_Name'

            if type == 'modifyStatus':
                status = param['Status']
                WhiteList.objects.filter(servername=server.servername, user=server.user, whitelist=ID,authmethod=authmethod).update(whitelist=ID, status=status)
                content = '修改登录保护状态：认证名：%s 状态为：%s' % (ID, status)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse("success")

            oldID = param['OldId']
            remark = param['Des']

            whitelists = WhiteList.objects.filter(servername=server.servername,user=server.user, whitelist=ID,authmethod=authmethod)
            if whitelists:
                WhiteList.objects.filter(servername=server.servername, user=server.user, whitelist=oldID, authmethod=authmethod).update(whitelist=ID,remark=remark)
                content = '修改登录保护：旧的认证名称是%s，新的名称为%s，备注为%s' % (oldID, ID, remark)
                addactionlog(server.user, server.servername, '系统防火墙', content)
            else:
                WhiteList.objects.create(servername=server.servername, user=server.user, whitelist=ID, authmethod=authmethod,remark=remark)
                content = '添加登录保护：名称为%s，备注为%s' % (ID, remark)
                addactionlog(server.user, server.servername, '系统防火墙', content)

        return HttpResponse("success")
    else:
        serverid = request.GET['serverid']
        if serverid:
            servername = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategyname = Strategy.objects.get(user=request.user, id=strategyid)

        whitelistid = request.GET['whitelistid']
        authmethod = request.GET['authmethod']
        newwhitelist = request.GET['whitelist']
        remark = request.GET['remark']

        # 判断要保存的白名单是否存在,存在更新、不存在新增
        if whitelistid:
            whitelists = WhiteList.objects.filter(whitelist=whitelistid)
            if whitelists:
                WhiteList.objects.filter(whitelist=whitelistid).update(whitelist=newwhitelist,remark=remark)
                content = '修改登录保护：旧的认证名称是%s，新的名称为%s，备注为%s' % (whitelistid, newwhitelist, remark)
                addactionlog(servername.user, servername.servername, '系统防火墙', content)
        else:
            if serverid:
                whiteLists = WhiteList.objects.filter(servername=servername, user=request.user, whitelist=newwhitelist)
                if whiteLists:
                    return HttpResponse("fail")
                else:
                    WhiteList.objects.create(servername=servername, user=request.user, whitelist=newwhitelist, remark=remark,authmethod=authmethod,status=False)
                content = '添加登录保护：名称为%s，备注为%s' % (newwhitelist, remark)
                addactionlog(servername.user, servername.servername, '系统防火墙', content)
            else:
                WhiteList.objects.create(servername=strategyname, user=request.user, whitelist=newwhitelist, remark=remark,authmethod=authmethod, status=False)

        whitelists = WhiteList.objects.filter(whitelist=newwhitelist)
        if whitelists:
            return HttpResponse("success")
        else:
            return HttpResponse("fail")

# 删除添加的白名单
def delwhitelist(request):
    logging.debug("delwhitelist")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        type = req['type']
        server = ServerTable.objects.get(serverip=ip)
    
        try:
            for param in params:
                ID = param['Id']
                WhiteList.objects.filter(servername=server.servername, user=server.user, whitelist=ID).delete()
                return HttpResponse('success')
        except:
            return HttpResponse('fail')
    else:
        selectwhitelistid = request.GET['selectwhitelistid']
        try:
            selectwhitelistid = selectwhitelistid.split(';')
            for whitelistid in selectwhitelistid:
                if whitelistid:
                    WhiteList.objects.filter(whitelist=whitelistid).delete()
            return HttpResponse("success")
        except:
            return HttpResponse("fail")


# 保存进程行为控制的策略
def processsolution(request):
    logging.debug("processsolution")
    serverid = request.GET['serverid']
    serverinfo = ServerTable.objects.filter(user=request.user, id=serverid)
    servername = serverinfo[0].servername;

    process_id = request.GET['process_id']
    obj = request.GET['obj']

    importprocess = ImportProcess.objects.get(id=process_id)
    if importprocess:
        if obj == 'stop':
            if importprocess.solution_stop:
                importprocess.solution_stop = False
            else:
                importprocess.solution_stop = True
        if obj == 'record':
            if importprocess.solution_record:
                importprocess.solution_record = False
            else:
                importprocess.solution_record = True

    importprocess.save()
    
    # ret = '{"process_id":%d,"solution_stop":%d,"solution_record":%d}' % (importprocess.id,importprocess.solution_stop,importprocess.solution_record)
    return HttpResponse('success')

# 添加操作日志
def addactionlog(user,servername,mode,content):
    date = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    
    logs = ActionLog.objects.all()
    n = len(logs)
    if n > 999:
        lastid = logs[n-999].id
        ActionLog.objects.filter(id__lt=lastid).delete()
    
    ActionLog.objects.create(user=user, servername=servername, actionmodel=mode,date=date,actioncontent=content)

# 账户保护
def saveusergroup(request):
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        type = req['type']
        server = ServerTable.objects.get(serverip=ip)

        try:
            # 账户保护
            for param in params:
                if 'modifyStatus' != type:
                    des = param['des']

                status = param['status']
                name = param['name']
                usergrouptype = param['type']

                # name为空，表示为全部一键操作指令
                if name == '':
                    usergroups = AccoutProt.objects.filter(user=server.user, servername=server.servername)
                    for usergroup in usergroups:
                        usergroup.usergroupstatus = status
                        usergroup.save()
                elif name == 'superManger' and 1 == usergrouptype:                         # 账户保护-超级管理员保护
                    server.nochangadmin_pass = status
                    server.save()
                elif name == 'userGroup' and 1 == usergrouptype:
                    server.usergroup_prot = status
                    server.save()
                else:
                    # 判断要保存的进程是否存在,存在更新、不存在新增
                    usergroups = AccoutProt.objects.filter(user=server.user,servername=server.servername,usergroup=name)
                    if usergroups:
                        AccoutProt.objects.filter(id=usergroups[0].id).update(usergroupstatus=status)
                        content = '用户组：%s 修改状态为：%s' % (name,status)
                        addactionlog(server.user, server.servername, '系统防火墙',content)
                    else:
                        AccoutProt.objects.create(servername=server.servername, user=server.user, usergroup=name, usergroupdes=des, usergroupstatus=status)
            return HttpResponse("success")
        except:
            return HttpResponse("fail")

# 后台通过websocket发送同步数据到客户端
def SendToClient(ip,msg,encrypted):
    url =  'ws://%s:8000' % (ip)
    if not encrypted:
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = msg.encode("utf-8")
        encryptedmsg = pc.encrypt(msg)
        msg = encryptedmsg
    try:
        client_ws = create_connection(url)
        client_ws.send(msg)
        client_ws.close()
        return True
    except:
        return False


# 保存进程行为控制中添加/修改的进程信息
def saveprocess(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip = GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        type = req['type']
        server = ServerTable.objects.get(serverip=ip)

        logging.debug("saveprocess Post")
        logging.debug(type)
        # 进程行为控制新增、修改规则
        oldPath = ''
        for param in params:
            solution_stop = False
            solution_record = False
            process_path = param['path']
            process_name = process_path.split("/")[-1]
            actionType = param['actionType']
            if actionType & 1:
                solution_stop = True
            if actionType & 2:
                solution_record = True

            if 'modifyStrategy' != type:
                oldPath = param['oldPath']
                ruleSel = param['ruleSel']
            elif 'modifyStrategy' == type:
                ImportProcess.objects.filter(processpath=process_path).update(solution_record=solution_record,solution_stop=solution_stop)
                content = '修改进程防护策略，进程名：%s 为记录%s，阻止%s' % (process_name, solution_record, solution_stop)
                addactionlog(server.user, server.servername, '系统防火墙', content)
                return HttpResponse("success")
                

            # 判断要保存的进程是否存在,存在更新、不存在新增
            # 旧路径和新路径相同
            if ''!= oldPath and oldPath == process_path:
                importprocesses = ImportProcess.objects.filter(servername = server.servername,user = server.user, processpath=process_path)
                # 数据库没有这条规则
                if not importprocesses:
                    ImportProcess.objects.create(servername=server.servername, user=server.user, sysrule=False,processname=process_name, processpath=process_path, ruleSel=ruleSel)
                    content = '添加新的进程：%s' % (process_name)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
                else:
                    ImportProcess.objects.filter(id=importprocesses[0].id).update(processname=process_name,processpath=process_path, ruleSel=ruleSel)
                    content = '修改进程：新进程名：%ss' % (process_name)
                    addactionlog(server.user, server.servername, '系统防火墙', content)
            else:
                # 新旧路径不相等，是修改
                importprocesses = ImportProcess.objects.filter(servername = server.servername,user = server.user,processpath=oldPath)
                ImportProcess.objects.filter(id=importprocesses[0].id).update(processname=process_name,processpath=process_path, ruleSel=ruleSel)
                content = '修改进程：新进程名：%s' % (process_name)
                addactionlog(server.user, server.servername, '系统防火墙', content)

            importprocesses = ImportProcess.objects.filter(processname=process_name)
            if not importprocesses:
                return HttpResponse("fail")
    else:
        logging.debug("saveprocess")
        serverid = request.GET['serverid']
        if serverid:
            servername = ServerTable.objects.get(user=request.user, id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategyname = Strategy.objects.get(user=request.user,id=strategyid)

        process_name = request.GET['process_name']
        process_path = request.GET['process_path']
        oldprocesspath = request.GET['oldprocesspath']
        ruleSel = request.GET['ruleSel']

        # 判断要保存的进程是否存在,存在更新、不存在新增
        if oldprocesspath:
            # 路径名称有变化
            if oldprocesspath != process_path:
                importprocesses = ImportProcess.objects.filter(processpath=process_path)
                if importprocesses:
                    logging.debug("SaveProcess:Exists process")
                    return HttpResponse("fail")
                # 新的名称与已有路径不重复
                else:
                    ImportProcess.objects.filter(processpath=oldprocesspath).update(processname=process_name,processpath=process_path,ruleSel=ruleSel)
                    content = '修改进程：新进程名：%s' % (process_name)
                    addactionlog(servername.user, servername.servername, '系统防火墙', content)
            else:
                importprocesses = ImportProcess.objects.filter(processpath=oldprocesspath)
                if importprocesses:
                    ImportProcess.objects.filter(id=importprocesses[0].id).update(processname=process_name,processpath=process_path,ruleSel=ruleSel)
                    content = '修改进程：新进程名：%s' % (process_name)
                    addactionlog(servername.user, servername.servername, '系统防火墙', content)
        else:
            importprocesses = ImportProcess.objects.filter(processpath=process_path)
            if importprocesses:
                logging.debug("Save Process:exists process")
                return HttpResponse("fail")
            if serverid:
                ImportProcess.objects.create(servername=servername,user=request.user, sysrule=False, processname = process_name, processpath=process_path,solution_stop=False,solution_record=False,ruleSel=ruleSel)
                content = '添加新的进程：%s' % (process_name)
                addactionlog(servername.user, servername.servername, '系统防火墙', content)
            else:
                ImportProcess.objects.create(servername=strategyname, user=request.user, sysrule=False,
                                             processname=process_name, processpath=process_path, solution_stop=False,
                                             solution_record=False, ruleSel=ruleSel)

        importprocesses = ImportProcess.objects.filter(processname=process_name)
        if importprocesses:
            return HttpResponse("success")
        else:
            return HttpResponse("fail")
        
# 删除添加的进程
def delprocess(request):
    logging.debug("delprocess")
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip= GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']

        server = ServerTable.objects.get(serverip=ip)

        for param in params:
            processpath = param
            ImportProcess.objects.filter(servername = server.servername, processpath=processpath).delete()

        return HttpResponse("success")
    selectprocessid = request.GET['selectprocessid']
    try:
        processidarray = selectprocessid.split(';')
        for processid in processidarray:
            if processid:
                ImportProcess.objects.filter(id=processid).delete()
        return HttpResponse("success")
    except:
        return HttpResponse("fail")

# 加密要发送的数据
def encryptmsg(request):
    msg = request.GET['msg']
    ip = request.GET['serverip']
    pc = prpcrypt("qazwsxedcrfvtgbh")
    msg = msg.encode("utf-8")
    encryptedmsg = pc.encrypt(msg)
    if SendToClient(ip,encryptedmsg,True):
        return HttpResponse('success')
    else:
        return HttpResponse('fail')

# 自定义设置规则 
def saverule(request):
    # 在设置中心、或者安全策略模版设置中添加规则
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)
        ip= GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']
        type = req['type']
        server = ServerTable.objects.get(serverip=ip)

        # 自定义规则保护-规则设置
        if method == 'fileProtect':
            featuremodule = 'file_prot'
        elif method == 'registerProtect':
            featuremodule = 'registry_prot'

        # 自定义规则更改状态
        if "modifyStatus" == type:
            for param in params:
                ruleName = param['ruleName']
                status = param['status']
                if '[系统]' in ruleName:
                    ruleName = ruleName.replace('[系统]', '')
                userrule = UserRule.objects.filter(servername=server.servername, rulename=ruleName)
                if userrule:
                    userrule[0].rulestatus = status
                    userrule[0].save()

                content = '修改规则状态：规则名%s,新状态为%s' % (ruleName, status)
                addactionlog(server.user, server.servername, '系统防火墙', content)

            return HttpResponse("success")

        # 自定义规则新增、修改规则
        for param in params:
            ruleoldname = param['oldRuleName']
            rulename = param['ruleName']
            rulepath = param['path']
            fileprottype = param['ruleType']
            forbidOpt = param['forbidOpt']
            ruleSel = param['ruleSel']

            forbidaction = ''
            if method == 'fileProtect':
                if forbidOpt & 1:
                    forbidaction += 'check_no_run;'
                if forbidOpt & 2:
                    forbidaction += 'check_no_del;'
                if forbidOpt & 4:
                    forbidaction += 'check_no_create;'
                if forbidOpt & 8:
                    forbidaction += 'check_no_read;'
                if forbidOpt & 16:
                    forbidaction += 'check_no_write;'

                if ruleSel & 1:
                    highindex = 0
                if ruleSel & 2:
                    highindex = 1
                if ruleSel & 4:
                    highindex = 2
                if ruleSel & 8:
                    highindex = 3
                if ruleSel & 16:
                    highindex = 4
                if ruleSel & 32:
                    highindex = 5

            elif method == 'registerProtect':
                if forbidOpt & 1:
                    forbidaction += 'check_no_del;'
                if forbidOpt & 2:
                    forbidaction += 'check_no_create;'
                if forbidOpt & 4:
                    forbidaction += 'check_no_write;'

                if ruleSel & 1:
                    highindex = 0
                if ruleSel & 2:
                    highindex = 1

            allowExts = ''
            refuseExts = ''
            allowFiles = ''
            refuseFiles = ''
            allowProcess = ''
            refuseProcess = ''

            if method == 'fileProtect':
                if param['allowExts']:
                    allowExts = param['allowExts']
                if param['refuseExts']:
                    refuseExts = param['refuseExts']
                if param['allowFiles']:
                    allowFiles = param['allowFiles']
                if param['refuseFiles']:
                    refuseFiles = param['refuseFiles']
                if param['allowProcess']:
                    allowProcess = param['allowProcess']
                if param['refuseProcess']:
                    refuseProcess = param['refuseProcess']
            elif method == 'registerProtect':
                if param['allowProcess']:
                    allowProcess = param['allowProcess']
                if param['refuseProcess']:
                    refuseProcess = param['refuseProcess']

            rulestatus = param['status']

            userrules = UserRule.objects.filter(servername= server.servername ,rulename=ruleoldname)
            if userrules:
                UserRule.objects.filter(id=userrules[0].id).update(featuremodule=featuremodule, rulename=rulename,rulepath=rulepath, rulestatus=rulestatus,forbidaction=forbidaction, fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles, refuseFiles=refuseFiles,allowProcess=allowProcess, refuseProcess=refuseProcess,highindex=highindex)
                content = '修改规则：%s，新规则名为：%s,新规则路径：%s，新状态为：%s' % (ruleoldname, rulename,rulepath,rulestatus)
                addactionlog(server.user, server.servername, '系统防火墙', content)
            else:
                UserRule.objects.create(servername=server.servername, featuremodule=featuremodule, user=server.user, rulename=rulename, rulepath=rulepath, rulestatus=rulestatus,forbidaction=forbidaction, fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles, refuseFiles=refuseFiles,allowProcess=allowProcess, refuseProcess=refuseProcess,highindex=highindex)
                content = '添加规则：%s 规则路径：%s' % (rulename, rulepath)
                addactionlog(server.user, server.servername, '系统防火墙', content)

        return HttpResponse("success")

    else:
        # 在设置中心、或者安全策略模版设置中添加规则
        logging.debug("addrule")
        serverid = request.GET['serverid']
        if serverid:
            server = ServerTable.objects.get(id=serverid)
        else:
            strategyid = request.GET['strategyid']
            strategyname = Strategy.objects.get(user=request.user, id=strategyid)

        rulename = request.GET['newrulename']
        oldrulename = request.GET['oldrulename']
        rulepath = request.GET['newrulepath']
        fileprottype = request.GET['fileprottype']
        forbidaction = request.GET['forbidaction']
        featuremodule = request.GET['feature']
        allowExts = request.GET['allowExts']
        allowFiles = request.GET['allowFiles']
        allowProcess = request.GET['allowProcess']
        refuseFiles = request.GET['refuseFiles']
        refuseProcess = request.GET['refuseProcess']
        refuseExts = request.GET['refuseExts']
        highsetindex = request.GET['highsetindex']


        # 判断要保存的规则是否存在,存在更新、不存在新增
        if oldrulename:
            if oldrulename == rulename:
                # 新旧规则名称一致，没有变化
                UserRule.objects.filter(user=server.user, servername=server.servername, rulename=oldrulename).update(featuremodule=featuremodule, rulepath=rulepath, forbidaction=forbidaction,fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles,refuseFiles=refuseFiles, allowProcess=allowProcess, refuseProcess=refuseProcess,highindex=highsetindex)
            else:
                #新旧规则不一致
                rules = UserRule.objects.filter(user=server.user, servername=server.servername, rulename=rulename,featuremodule=featuremodule)
                # 新规则存在且新旧规则名不一致
                if rules:
                    # 新规名称存在了
                    logging.debug("Saverule:Exists rule")
                    return HttpResponse("fail")
                else:
                    UserRule.objects.filter(user=server.user, servername=server.servername,rulename=oldrulename).update(featuremodule=featuremodule,rulename=rulename,rulepath=rulepath,forbidaction=forbidaction,fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles,refuseFiles=refuseFiles,allowProcess=allowProcess, refuseProcess=refuseProcess, highindex = highsetindex)
            content = '修改规则：%s，新规则名为：%s,新规则路径：%s ' % (oldrulename, rulename, rulepath)
            addactionlog(server.user, server.servername, '系统防火墙', content)
        else:
            # 判断要新增的规则是否存在，存在即返回错误
            userrules = UserRule.objects.filter(user=server.user,servername=server.servername,rulename=rulename,featuremodule=featuremodule)
            if userrules:
                logging.debug("Saverule:Exists rule")
                return HttpResponse("fail")
            if serverid:
                UserRule.objects.create(servername=server.servername,featuremodule=featuremodule,user=request.user,rulename=rulename,rulepath=rulepath,rulestatus=False,forbidaction=forbidaction,fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles, refuseFiles=refuseFiles,allowProcess=allowProcess, refuseProcess=refuseProcess, highindex = highsetindex)
                content = '添加规则：%s 规则路径：%s' % (rulename, rulepath)
                addactionlog(server.user, server.servername, '系统防火墙', content)
            else:
                UserRule.objects.create(servername=strategyname, featuremodule=featuremodule, user=request.user,rulename=rulename, rulepath=rulepath, rulestatus=False,forbidaction=forbidaction, fileprottype=fileprottype, allowExts=allowExts, refuseExts=refuseExts, allowFiles=allowFiles, refuseFiles=refuseFiles,allowProcess=allowProcess, refuseProcess=refuseProcess, highindex = highsetindex)

        userrules = UserRule.objects.filter(user=server.user,servername=server.servername,rulename=rulename,featuremodule=featuremodule)
        if userrules:
            return HttpResponse("success")
        else:
            logging.debug("Saverule:fail")
            return HttpResponse("fail")
        
# 删除自定义规则
def delrule(request):
    logging.debug("delrule")
    # 处理POST请求，就是客户端同步过来的操作
    if request.method == 'POST':
        pc = prpcrypt("qazwsxedcrfvtgbh")
        msg = pc.decrypt(request.body)
        req = json.loads(msg)

        ip= GetRequestIP(request)
        if ip == '127.0.0.1':
            ip = req['ip']

        method = req['method']
        params = req['param']

        server = ServerTable.objects.get(serverip=ip)

        for param in params:
            rulename = param
            UserRule.objects.filter(servername = server.servername, rulename=rulename).delete()

        return HttpResponse("success")

    selectruleid = request.GET['selectruleid']
    try:
        ruleidarray = selectruleid.split(';')
        for ruleid in ruleidarray:
            if ruleid:
                UserRule.objects.filter(id=ruleid).delete()
        return HttpResponse("success")
    except:
        return HttpResponse("fail")

# 服务器分组设置
def groupset(request):
    logging.debug("addgroup")
    obj = request.GET['obj']
    if 'newgroup' == obj:
        logging.debug(obj)
        newgroupname = request.GET['newgroupname']
        if '未分组' == newgroupname or '' == newgroupname or ' ' in newgroupname:
            return HttpResponse("fail")
        servergroups = ServerGroup.objects.filter(user=request.user, groupname=newgroupname)
        if servergroups:
            return HttpResponse("fail")

        # newgroupcode = base64.b64decode(newgroupname)
        newgroupcode = base64.b64encode(newgroupname)
        ServerGroup.objects.create(user=request.user, groupname=newgroupname, groupcode=newgroupcode)
        servergroup = ServerGroup.objects.filter(groupname=newgroupname)
        if servergroup:
            logging.debug(servergroup)
            return HttpResponse("success")
        else:
            return HttpResponse("fail")
    elif 'delgroup' == obj:
        selgroup = request.GET['delgroup']
        grouparray = selgroup.split(';')
        if delgroup(grouparray,request.user):
            return HttpResponse("success")
        else:
            return HttpResponse("fail")
        
# 设置报警邮箱 
def setemail(request):
    logging.debug("setemail_debug")
    obj = request.GET['obj']
    logging.debug(obj)
    newemail = request.GET['newemail']
    logging.debug(newemail)
    
    Profile.objects.filter(user=request.user).update(alarm_email=newemail)    
    user = Profile.objects.filter(user=request.user)
    
    if user[0].alarm_email == newemail:
        return HttpResponse("success")
    else:
        return HttpResponse("fail")
        
# 设置报警手机 
def setphone(request):
    logging.debug("setphone_debug")
    obj = request.GET['obj']
    logging.debug(obj)
    newphone = request.GET['newphone']
    logging.debug(newphone)
    
    Profile.objects.filter(user=request.user).update(alarm_phone=newphone)    
    user = Profile.objects.filter(user=request.user)
    
    if user[0].alarm_phone == newphone:
        return HttpResponse("success")
    else:
        return HttpResponse("fail")

 
# 添加备注
def addremark(request):
    logging.debug("addremark_debug")
    remark = request.GET['remark']
    logging.debug(remark)
    remarkserverid = request.GET['remarkserverid']
    logging.debug(remarkserverid)
    ServerTable.objects.filter(user=request.user,id=remarkserverid).update(serverremark=remark)
    serverinfo = ServerTable.objects.filter(user=request.user,id=remarkserverid)
    
    if serverinfo[0].serverremark == remark:
        return HttpResponse("success")
    else:
        return HttpResponse("fail")

# 下载安装包
def downclient(request):
    return HttpResponse("success")
 
@ajax_required
@require_POST
@login_required
def user_follow(request):
    user_id = request.POST.get('id')
    action = request.POST.get('action')
    if user_id and action:
        try:
            user = User.objects.get(id=user_id)
            if action == 'follow':
                Contact.objects.get_or_create(user_from=request.user,user_to=user)
                # create_action(request.user, 'is following', user)
            else:
                Contact.objects.filter(user_from=request.user,
                                       user_to=user).delete()
            return JsonResponse({'status':'ok'})
        except User.DoesNotExist:
            return JsonResponse({'status':'ko'})
    return JsonResponse({'status':'ko'})


def savesetting(profile,alarmWays):
    # 账户保护
    if '151' in alarmWays:           
        profile.account_prot = 2
    else:
        if '152' not in alarmWays:
            profile.account_prot = 0
     
    if '152' in alarmWays:
        profile.account_prot = 1
        if '151' in alarmWays:
            profile.account_prot = 3

    # 文件保护
    if '1' in alarmWays:           
        profile.file_prot = 2
    else:
        if '2' not in alarmWays:
            profile.file_prot = 0
     
    if '2' in alarmWays:
        profile.file_prot = 1
        if '1' in alarmWays:
            profile.file_prot = 3
    
    # 注册表保护
    if '11' in alarmWays:           
        profile.registry_prot = 2
    else:
        if '12' not in alarmWays:
            profile.registry_prot = 0
     
    if '12' in alarmWays:
        profile.registry_prot = 1
        if '11' in alarmWays:
            profile.registry_prot = 3
            
    # 受控项目
    if '131' in alarmWays:           
        profile.controlled_pro = 2
    else:
        if '132' not in alarmWays:
            profile.controlled_pro = 0
     
    if '132' in alarmWays:
        profile.controlled_pro = 1
        if '131' in alarmWays:
            profile.controlled_pro = 3
            
    # 进程行为控制
    if '141' in alarmWays:           
        profile.process_behavior = 2
    else:
        if '142' not in alarmWays:
            profile.process_behavior = 0
     
    if '142' in alarmWays:
        profile.process_behavior = 1
        if '141' in alarmWays:
            profile.process_behavior = 3
            
    # Web威胁
    if '21' in alarmWays:           
        profile.Web_menace = 2
    else:
        if '22' not in alarmWays:
            profile.Web_menace = 0
     
    if '22' in alarmWays:
        profile.Web_menace = 1
        if '21' in alarmWays:
            profile.Web_menace = 3
    
    # 恶意软件和PUA
    if '31' in alarmWays:           
        profile.malice_software = 2
    else:
        if '32' not in alarmWays:
            profile.malice_software = 0
     
    if '32' in alarmWays:
        profile.malice_software = 1
        if '31' in alarmWays:
            profile.malice_software = 3
                
    # SYN攻击
    if '51' in alarmWays:           
        profile.SYN_attack = 2
    else:
        if '52' not in alarmWays:
            profile.SYN_attack = 0
     
    if '52' in alarmWays:
        profile.SYN_attack = 1
        if '51' in alarmWays:
            profile.SYN_attack = 3
    
    # 扫描攻击
    if '61' in alarmWays:           
        profile.scan_attack = 2
    else:
        if '62' not in alarmWays:
            profile.scan_attack = 0
     
    if '62' in alarmWays:
        profile.scan_attack = 1
        if '61' in alarmWays:
            profile.scan_attack = 3
            
    # 流量攻击
    if '71' in alarmWays:           
        profile.flow_attack = 2
    else:
        if '72' not in alarmWays:
            profile.flow_attack = 0
     
    if '72' in alarmWays:
        profile.flow_attack = 1
        if '71' in alarmWays:
            profile.flow_attack = 3
            
    # MySQL暴力破解
    if '41' in alarmWays:           
        profile.MySQL_avoidviolence = 2
    else:
        if '42' not in alarmWays:
            profile.MySQL_avoidviolence = 0
     
    if '42' in alarmWays:
        profile.MySQL_avoidviolence = 1
        if '41' in alarmWays:
            profile.MySQL_avoidviolence = 3
            
    # MSSQL防暴力破解
    if '81' in alarmWays:           
        profile.MSSQL_avoidviolence = 2
    else:
        if '82' not in alarmWays:
            profile.MSSQL_avoidviolence = 0
     
    if '82' in alarmWays:
        profile.MSSQL_avoidviolence = 1
        if '81' in alarmWays:
            profile.MSSQL_avoidviolence = 3
            
    
            
    # CPU使用率太高
    if '91' in alarmWays:           
        profile.CPU_highusage = 2
    else:
        if '92' not in alarmWays:
            profile.CPU_highusage = 0
     
    if '92' in alarmWays:
        profile.CPU_highusage = 1
        if '91' in alarmWays:
            profile.CPU_highusage = 3
            
    # 硬盘使用率太高
    if '101' in alarmWays:           
        profile.harddisk_highusage = 2
    else:
        if '102' not in alarmWays:
            profile.harddisk_highusage = 0
     
    if '102' in alarmWays:
        profile.harddisk_highusage = 1
        if '101' in alarmWays:
            profile.harddisk_highusage = 3
            
    # 内存使用率太高
    if '111' in alarmWays:           
        profile.RAM_highusage = 2
    else:
        if '112' not in alarmWays:
            profile.RAM_highusage = 0
     
    if '112' in alarmWays:
        profile.RAM_highusage = 1
        if '111' in alarmWays:
            profile.RAM_highusage = 3
            
    # 网络流量超过负荷
    if '121' in alarmWays:           
        profile.networkflow_highusage = 2
    else:
        if '122' not in alarmWays:
            profile.networkflow_highusage = 0
     
    if '122' in alarmWays:
        profile.networkflow_highusage = 1
        if '121' in alarmWays:
            profile.networkflow_highusage = 3
            
            
    profile.save()