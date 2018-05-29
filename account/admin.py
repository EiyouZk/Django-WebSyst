from django.contrib import admin
from .models import Profile,ServerTable,ServerGroup,ServerStatus,ServerNotice,ActionLog,UserRule,ImportProcess,WhiteList,SuperList,InterceptIP,AppControl,AccoutProt,OutsideDevice,PortSecurity,ServerGateway,NetFirewall,UrlWhiteList,Strategy,PortIpSegment


class ProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'date_of_birth', 'smsnbalance','verify_email','alarm_email','alarm_phone','file_prot','registry_prot','controlled_pro','process_behavior','Web_menace','malice_software','SYN_attack','scan_attack','flow_attack','CPU_highusage','harddisk_highusage','RAM_highusage','networkflow_highusage']

class ServerTableAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'protected_days','serverip','serverstatus','servergroup','account_prot','file_prot','registry_prot','process_behavior','outside_control','app_control','remote_login_remind','whitelist_access_control','ARPfirwall','DDosfirwall','Web_firwall','FTP_avoidviolence','ReDesktop_avoidviolence','MySQL_avoidviolence','MSSQL_avoidviolence','port_security','super_blacklist','super_whitelist']
	
class ServerGroupAdmin(admin.ModelAdmin):
    list_display = ['groupname','user', 'groupcode', 'groupnum']
	
class ServerStatusAdmin(admin.ModelAdmin):
    list_display = ['statusname', 'statuscode', 'statusnum']
	
class ServerNoticeAdmin(admin.ModelAdmin):
    list_display = ['user','servername', 'noticereason', 'noticetype','noticedate','noticecontent','noticemethod','defendresult']
	
class ActionLogAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'actionmodel','date','actioncontent','processpath','defendresult']

class UserRuleAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'featuremodule','rulename','rulepath','rulestatus','forbidaction','fileprottype']
	
class ImportProcessAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'processname','sysrule','processpath','ruleSel','solution_stop','solution_record']

class WhiteListAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'whitelist','remark','authmethod','status']	
	
class SuperListAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'listtype','addr','ipremark','startip','endip','ipsremark']

class InterceptIPAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'type','ip','port','postion','remaintime','intercepttype']
	
class AppControlAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'apptype','appname','remark','solution_stop','solution_record']

class AccoutProtAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'usergroup','usergroupdes','usergroupstatus']
	
class OutsideDevicelAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'devicetype','devicename','remark','solution_stop','solution_record']	
	
class PortIpSegmentAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'port','startip','endip']

class PortSecurityAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'port','protocol','rule','exception','solution_stop','solution_record','exceptionvalue']

class ServerGatewayAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'IP','MAC','gatewayip','gatewaymac','connectname']
	
class NetFirewallAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'InterceptExternalARPAttacks','FTP_Seconds', 'RemoteDesktop_Seconds','MySqlDB_Seconds', 'MSSqlDB_Seconds','SYNAttack_Seconds', 'WebFirewall_Seconds','WebFirewal_VerifySessionOn']

class UrlWhiteListAdmin(admin.ModelAdmin):
    list_display = ['servername', 'user', 'url','remark']	

class StrategyAdmin(admin.ModelAdmin):
    list_display = ['user', 'strategyname','type', 'time', 'count']		
	
admin.site.register(Profile, ProfileAdmin)
admin.site.register(ServerTable,ServerTableAdmin)
admin.site.register(ServerGroup,ServerGroupAdmin)
admin.site.register(ServerStatus,ServerStatusAdmin)
admin.site.register(ServerNotice,ServerNoticeAdmin)
admin.site.register(ActionLog,ActionLogAdmin)
admin.site.register(UserRule,UserRuleAdmin)
admin.site.register(ImportProcess,ImportProcessAdmin)
admin.site.register(WhiteList,WhiteListAdmin)
admin.site.register(SuperList,SuperListAdmin)
admin.site.register(InterceptIP,InterceptIPAdmin)
admin.site.register(AppControl,AppControlAdmin)
admin.site.register(AccoutProt,AccoutProtAdmin)
admin.site.register(OutsideDevice,OutsideDevicelAdmin)
admin.site.register(PortSecurity,PortSecurityAdmin)
admin.site.register(PortIpSegment,PortIpSegmentAdmin)
# admin.site.register(CustomizeGateway,CustomizeGatewayAdmin)
admin.site.register(ServerGateway,ServerGatewayAdmin)
admin.site.register(NetFirewall,NetFirewallAdmin)
admin.site.register(UrlWhiteList,UrlWhiteListAdmin)
admin.site.register(Strategy,StrategyAdmin)