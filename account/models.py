#!/usr/bin/python
#-*-coding:utf-8 -*-

from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
import django.utils.timezone as timezone

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL)
    date_of_birth = models.DateField(blank=True, null=True)
    smsnbalance = models.IntegerField(default=0)
    verify_email = models.EmailField(blank=True)
    alarm_email = models.EmailField(blank=True)
    alarm_phone = models.CharField(max_length=13,blank=True)
	
    account_prot = models.IntegerField(default=0) 
    file_prot = models.IntegerField(default=0)   
    registry_prot = models.IntegerField(default=0)
    controlled_pro = models.IntegerField(default=0)
    process_behavior = models.IntegerField(default=0)
	
    Web_menace = models.IntegerField(default=0)    
    malice_software = models.IntegerField(default=0)    
    SYN_attack = models.IntegerField(default=0)    
    scan_attack = models.IntegerField(default=0)   
    flow_attack = models.IntegerField(default=0) 
    MySQL_avoidviolence = models.IntegerField(default=0)   
    MSSQL_avoidviolence = models.IntegerField(default=0) 

    CPU_highusage = models.IntegerField(default=0)    
    harddisk_highusage = models.IntegerField(default=0)    
    RAM_highusage = models.IntegerField(default=0)    
    networkflow_highusage = models.IntegerField(default=0)

    profileID = models.CharField(max_length=256, blank=True)

    class Meta:
        verbose_name = u'用户'
        verbose_name_plural = u'用户'
        
    
    
    def __str__(self):
        return 'Profile for user {}'.format(self.user.username)

class ServerTable(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    protected_days = models.CharField(max_length=100,default='')
    bisonline = models.IntegerField(default=0)
    serverremark = models.CharField(max_length=100,default="",blank=True)
    serverip = models.CharField(max_length=100)
    strategyname = models.CharField(max_length=100,default="自定义模版")
    lastlogin = models.CharField(max_length=100)
	
    serverstatus = models.CharField(max_length=8,default="Normal")
    servergroup = models.CharField(max_length=8,default="Un_Group",blank=True)
    networkUpFlow = models.CharField(max_length=256,default="0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;")
    networkDownFlow = models.CharField(max_length=256, default="0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;")

    ARPoutattack = models.IntegerField(default=0)
    ARPfobattack = models.IntegerField(default=0)
    ARPIPclashattack = models.IntegerField(default=0)
    DDosUDPattack = models.IntegerField(default=0)
    DDosscanattack = models.IntegerField(default=0)
    DDosICMPattack = models.IntegerField(default=0)
    WebCCattack = models.IntegerField(default=0)
    APPremotedeskattack = models.IntegerField(default=0)
    SYNattack = models.IntegerField(default=0)
    Ftpattack = models.IntegerField(default=0)
    MySqlattack = models.IntegerField(default=0)
    MSSqlattack = models.IntegerField(default=0)
    attackcount = models.IntegerField(default=0)

    logincity = models.CharField(max_length=32,default='')
    commonlogincitya = models.CharField(max_length=32,default='',blank=True)
    commonlogincityb = models.CharField(max_length=32, default='',blank=True)
    remoteloginnotice = models.IntegerField(default=0)

	# 设置中心-系统防火墙
    account_prot = models.BooleanField(default=False)  
    file_prot = models.BooleanField(default=True)
    registry_prot = models.BooleanField(default=True)
    process_behavior = models.BooleanField(default=True)
    outside_control = models.BooleanField(default=False)

    bluetooth = models.BooleanField(default=False)
    opticaldrive = models.BooleanField(default=False)
    wirelessdevice = models.BooleanField(default=False)
    mobiledevice = models.BooleanField(default=False)

    app_control = models.BooleanField(default=False)
    remote_login_remind = models.BooleanField(default=False)
    whitelist_access_control = models.BooleanField(default=False)
	
    ARPfirwall = models.BooleanField(default=False)
    DDosfirwall = models.BooleanField(default=False)
    Web_firwall = models.BooleanField(default=False)
    FTP_avoidviolence = models.BooleanField(default=False)
    ReDesktop_avoidviolence = models.BooleanField(default=False)
    MySQL_avoidviolence = models.BooleanField(default=False)
    MSSQL_avoidviolence = models.BooleanField(default=False)
	
    port_security = models.BooleanField(default=False)
    forbid_ping = models.BooleanField(default=False)
    super_blacklist = models.BooleanField(default=False)
    super_whitelist = models.BooleanField(default=False)

    result_registry = models.CharField(max_length=512,default='',blank=True)
    update_registry = models.BooleanField(default=False,blank=True)
    result_service = models.CharField(max_length=512, default='', blank=True)
    update_service = models.BooleanField(default=False, blank=True)
    result_account = models.CharField(max_length=512, default='', blank=True)
    update_account = models.BooleanField(default=False, blank=True)
	
	# 账户保护-规则
    nochangadmin_pass = models.BooleanField(default=False)
    usergroup_prot = models.BooleanField(default=False)
	
    class Meta:
        verbose_name = u'用户服务器'
        verbose_name_plural = u'用户服务器'
    
    def __str__(self):
        return self.servername 
		
class ServerGroup(models.Model):
    user = models.CharField(max_length=100,default="")
    groupname = models.CharField(max_length=100)
    groupcode = models.CharField(max_length=200)
    groupnum = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = u'服务器分组表'
        verbose_name_plural = u'服务器分组表'
    
    def __str__(self):
        return self.groupname

class ServerStatus(models.Model):
    statusname = models.CharField(max_length=100)
    statuscode = models.CharField(max_length=8)
    statusnum = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = u'服务器状态表'
        verbose_name_plural = u'服务器状态表'
    
    def __str__(self):
        return self.statusname 

class ServerNotice(models.Model):
    user = models.CharField(max_length=100,null=True)
    servername = models.CharField(max_length=100)
    noticereason = models.CharField(max_length=100)
    noticetype = models.CharField(max_length=100)
    noticedate = models.DateTimeField()
    noticecontent = models.CharField(max_length=1000,default="")
    noticemethod = models.CharField(max_length=16,default="未通知")
    defendresult = models.CharField(max_length=20, default='')
	
    class Meta:
        verbose_name = u'历史报警'
        verbose_name_plural = u'历史报警表'
    
    def __str__(self):
        return self.noticereason 
		
class ActionLog(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    actionmodel = models.CharField(max_length=100)
    date = models.CharField(max_length=20)
    actioncontent = models.CharField(max_length=200)
    processpath = models.CharField(max_length=200,default='')
    defendresult = models.CharField(max_length=20,default='')
    
    class Meta:
        verbose_name = u'操作日志'
        verbose_name_plural = u'客户端操作日志'
        
    def __str__(self):
        return self.actionmodel
	
# 文件保护、注册表保护中的自定义规则	
class UserRule(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    featuremodule = models.CharField(max_length=20,default="")
    rulename = models.CharField(max_length=50)
    rulepath = models.CharField(max_length=100)
    rulestatus = models.BooleanField(default=False)
    forbidaction = models.CharField(max_length=100)
    fileprottype = models.IntegerField(default=0)

    allowExts = models.CharField(max_length=100,default="")
    allowFiles = models.CharField(max_length=100, default="")
    allowProcess = models.CharField(max_length=100, default="")
    refuseExts = models.CharField(max_length=100, default="")
    refuseFiles = models.CharField(max_length=100, default="")
    refuseProcess = models.CharField(max_length=100, default="")
    highindex = models.IntegerField(default=0)

	
    class Meta:
        verbose_name = u'保存用户对某台服务器的自定义规则'
        verbose_name_plural = u'自定义规则'
        
    def __str__(self):
        return self.rulename

# 进程行为控制中重要进程
class ImportProcess(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    processname = models.CharField(max_length=50)
    sysrule = models.BooleanField(default=False)
    processpath = models.CharField(max_length=100)
    solution_stop = models.BooleanField(default=False)
    solution_record = models.BooleanField(default=False)
    ruleSel = models.IntegerField(default=0)
	
    class Meta:
        verbose_name = u'保存用户设置的重要进程'
        verbose_name_plural = u'进程行为控制'
        
    def __str__(self):
        return self.processname
	
# 登录保护中的白名单	
class WhiteList(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    whitelist = models.CharField(max_length=50)
    remark = models.CharField(max_length=100)
    authmethod = models.CharField(max_length=100)
    status = models.BooleanField(default=False)
	
    class Meta:
        verbose_name = u'保存用户设置的白名单'
        verbose_name_plural = u'白名单'
        
    def __str__(self):
        return self.whitelist
		
# 超级黑白名单	
class SuperList(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    listtype = models.CharField(max_length=16)
    addr = models.GenericIPAddressField(null=True,blank=True)
    ipremark = models.CharField(max_length=100,default='',blank=True)
    startip = models.GenericIPAddressField(null=True,blank=True)
    endip = models.GenericIPAddressField(null=True,blank=True)
    ipsremark = models.CharField(max_length=100,default='',blank=True)
	
    class Meta:
        verbose_name = u'保存用户设置的超级黑白名单'
        verbose_name_plural = u'超级黑白名单'
        
    def __str__(self):
        return self.servername

# IP拦截监控
class InterceptIP(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    type = models.CharField(max_length=16)
    ip = models.GenericIPAddressField(null=True, blank=True)
    port = models.CharField(max_length=16)
    postion = models.CharField(max_length=100, default='', blank=True)
    remaintime = models.CharField(max_length=16)
    intercepttype = models.CharField(max_length=16)

    class Meta:
        verbose_name = u'保存服务器的冻结IP和放行IP列表和信息'
        verbose_name_plural = u'IP拦截监控'

    def __str__(self):
        return self.servername
		
# 应用程序控制	
class AppControl(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    apptype = models.CharField(max_length=12)
    appname = models.CharField(max_length=50)
    remark = models.CharField(max_length=100)
    solution_stop = models.BooleanField(default=False)
    solution_record = models.BooleanField(default=False)
	
    class Meta:
        verbose_name = u'保存用户控制的应用程序'
        verbose_name_plural = u'应用程序控制'
        
    def __str__(self):
        return self.appname

# 账户保护
class AccoutProt(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    usergroup = models.CharField(max_length=128)
    usergroupdes = models.CharField(max_length=256)
    usergroupstatus = models.BooleanField(default=False)

    class Meta:
        verbose_name = u'保存服务器的用户组信息'
        verbose_name_plural = u'账户保护'

    def __str__(self):
        return self.usergroup

		
# 外围设备控制	
class OutsideDevice(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    devicetype = models.CharField(max_length=12)
    devicename = models.CharField(max_length=50)
    remark = models.CharField(max_length=100)
    solution_stop = models.BooleanField(default=False)
    solution_record = models.BooleanField(default=False)
	
    class Meta:
        verbose_name = u'保存用户控制的外围设备'
        verbose_name_plural = u'外围设备控制'
        
    def __str__(self):
        return self.devicename
    

# 端口安全策略	
class PortSecurity(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    port = models.CharField(max_length=10)
    protocol = models.CharField(max_length=10)
    rule = models.CharField(max_length=50,default='reject all IP')
    exception = models.CharField(max_length=100)
    rulemode = models.CharField(max_length=50,default='permanently effective')
    solution_stop = models.BooleanField(default=False)
    solution_record = models.BooleanField(default=False)
    exceptionvalue = models.CharField(max_length=512,default='')
	
    class Meta:
        verbose_name = u'保存用户设置端口安全策略'
        verbose_name_plural = u'端口安全策略'
        
    def __str__(self):
        return self.port

# 端口安全策略的IP地址段
class PortIpSegment(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    port = models.CharField(max_length=10)
    protocol = models.CharField(max_length=10,default='')
    startip = models.GenericIPAddressField(default='192.168.0.1')
    endip = models.GenericIPAddressField(default='192.168.0.1')

    class Meta:
        verbose_name = u'保存端口安全策略ip地址段'
        verbose_name_plural = u'端口安全策略的ip地址段'

    def __str__(self):
        return self.port


# # 自定义网关IP和MAC
# class CustomizeGateway(models.Model):
#     servername = models.CharField(max_length=100)
#     user = models.CharField(max_length=100)
#     IP = models.CharField(max_length=16)
#     MAC = models.CharField(max_length=24)
#     gatewayip = models.CharField(max_length=16)
#     gatewaymac = models.CharField(max_length=24)
#
#     class Meta:
#         verbose_name = u'自定义网关IP和MAC绑定规则列表'
#         verbose_name_plural = u'自定义网关'
#
#     def __str__(self):
#         return self.IP

# 自定义网关IP和MAC
class ServerGateway(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    IP = models.CharField(max_length=16)
    MAC = models.CharField(max_length=24)
    gatewayip = models.CharField(max_length=16)
    gatewaymac = models.CharField(max_length=24)
    connectname = models.CharField(max_length=128)

    class Meta:
        verbose_name = u'服务器网关IP和MAC信息'
        verbose_name_plural = u'服务器网关'

    def __str__(self):
        return self.IP

		
# 网络防火墙设置 在新增服务器的时候就需要建立一条网络防火墙的记录
class NetFirewall(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)

    mode = models.IntegerField(default=0)
    Auto_IP = models.CharField(max_length=16,default='')
    Auto_MAC = models.CharField(max_length=24,default='')
    Auto_GatewayIP = models.CharField(max_length=16, default='')
    Auto_GatewayMAC = models.CharField(max_length=24, default='')

    IP = models.CharField(max_length=16,default='')
    MAC = models.CharField(max_length=24,default='')
    GatewayIP = models.CharField(max_length=16,default='')
    GatewayMAC = models.CharField(max_length=24,default='')

    InterceptExternalARPAttacks = models.BooleanField(default=True)
    InterceptLocalARPAttacks = models.BooleanField(default=False)
    InterceptIPConflict = models.BooleanField(default=False)
    LANStealth = models.BooleanField(default=False)

    FTP_Seconds = models.IntegerField(default=60)
    FTP_Times = models.IntegerField(default=10)
    FTP_IPFreezeTime = models.IntegerField(default=10)
    FTP_ProtPort = models.CharField(max_length=128,default='')
    RemoteDesktop_Seconds= models.IntegerField(default=60)
    RemoteDesktop_Times = models.IntegerField(default=10)
    RemoteDesktop_IPFreezeTime = models.IntegerField(default=10)
    MySqlDB_Seconds = models.IntegerField(default=60)
    MySqlDB_Times = models.IntegerField(default=10)
    MySqlDB_IPFreezeTime = models.IntegerField(default=10)
    MySqlDB_ProtPort = models.CharField(max_length=128,default='')
    MSSqlDB_Seconds = models.IntegerField(default=60)
    MSSqlDB_Times = models.IntegerField(default=10)
    MSSqlDB_IPFreezeTime = models.IntegerField(default=10)

    SYNAttack_Seconds = models.IntegerField(default=0)
    SYNAttack_times = models.IntegerField(default=0)
    ScanAttack_Seconds = models.IntegerField(default=0)
    ScanAttack_times = models.IntegerField(default=0)
    FlowAttack_ICMP_Seconds = models.IntegerField(default=0)
    FlowAttack_ICMP_times = models.IntegerField(default=0)
    FlowAttack_UDP_Seconds = models.IntegerField(default=0)
    FlowAttack_UDP_times = models.IntegerField(default=0)
    DDoS_IPFreezeTime = models.IntegerField(default=0)

    WebFirewall_Seconds = models.IntegerField(default=10)
    WebFirewall_Times = models.IntegerField(default=300)
    WebFirewall_IPFreezeTime = models.IntegerField(default=10)
    WebFirewall_IPAllowTime = models.IntegerField(default=10)
    WebFirewal_ProtPort = models.CharField(max_length=100)
    WebFirewal_VerifySessionOn = models.BooleanField(default=False)
    WebFirewal_VerifySessionLevel = models.IntegerField(default=0)
    WebFirewal_AgentMaxIPs = models.IntegerField(default=30)
    WebFirewal_AgentTime = models.IntegerField(default=30)

    class Meta:
        verbose_name = u'保存网络防火墙的设置'
        verbose_name_plural = u'网络防火墙'
        
    def __str__(self):
        return self.servername
	
# 网络防火墙URL白名单
class UrlWhiteList(models.Model):
    servername = models.CharField(max_length=100)
    user = models.CharField(max_length=100)
    url = models.CharField(max_length=16)
    remark = models.CharField(max_length=24)
	
    class Meta:
        verbose_name = u'网络防火墙URL白名单'
        verbose_name_plural = u'URL白名单'
        
    def __str__(self):
        return self.url	
		
# 自定义安全策略模版表
class Strategy(models.Model):
    user = models.CharField(max_length=100)
    strategyname = models.CharField(max_length=32)
    type = models.CharField(max_length=24)
    time = models.DateTimeField(auto_now_add=True, db_index=True)
    count = models.IntegerField(default=0)
    source = models.CharField(max_length=24,default='user')

    commonlogincitya = models.CharField(max_length=32, default='')
    commonlogincityb = models.CharField(max_length=32, default='')
    remoteloginnotice = models.IntegerField(default=0)

    # 设置中心-系统防火墙
    account_prot = models.BooleanField(default=False)  
    file_prot = models.BooleanField(default=False)   
    registry_prot = models.BooleanField(default=False)
    process_behavior = models.BooleanField(default=False)
    outside_control = models.BooleanField(default=False)
    app_control = models.BooleanField(default=False)
    remote_login_remind = models.BooleanField(default=False)
    whitelist_access_control = models.BooleanField(default=False)
	
    ARPfirwall = models.BooleanField(default=False)
    DDosfirwall = models.BooleanField(default=False)
    Web_firwall = models.BooleanField(default=False)
    FTP_avoidviolence = models.BooleanField(default=False)
    ReDesktop_avoidviolence = models.BooleanField(default=False)
    MySQL_avoidviolence = models.BooleanField(default=False)
    MSSQL_avoidviolence = models.BooleanField(default=False)
	
    port_security = models.BooleanField(default=False)
    forbid_ping = models.BooleanField(default=False)
    super_blacklist = models.BooleanField(default=False)
    super_whitelist = models.BooleanField(default=False)

	# 账户保护-规则
    nochangadmin_pass = models.BooleanField(default=False)
    usergroup_prot = models.BooleanField(default=False)
	
    class Meta:
        verbose_name = u'用户自己添加安全策略模版'
        verbose_name_plural = u'自定义策略'
        
    def __str__(self):
        return self.strategyname	
	
class Contact(models.Model):
    user_from = models.ForeignKey(User,related_name='rel_from_set')
    user_to = models.ForeignKey(User, related_name='rel_to_set')
    created = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ('-created',)

    def __str__(self):
        return '{} follows {}'.format(self.user_from, self.user_to)		


# Add following field to User dynamically
User.add_to_class('following',
                  models.ManyToManyField('self',
                                         through=Contact,
                                         related_name='followers',
                                         symmetrical=False))
