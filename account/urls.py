from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^login/$', views.user_login, name='login'),
    url(r'^$', views.index, name='index'),
    url(r'^cloudset/$', views.cloudset, name='cloudset'),
    url(r'^setting/$', views.setting, name='setting'),
    url(r'^strategy/$', views.strategy, name='strategy'),
    url(r'^strategylinux/$', views.strategylinux, name='strategylinux'),
    url(r'^strategytemp/$', views.strategytemp, name='strategytemp'),	
    url(r'^securityset/$', views.securityset, name='securityset'),
    url(r'^singleserver/$', views.singleserver, name='singleserver'),	
    url(r'^protectset/$', views.protectset, name='protectset'),	
    url(r'^sysfirewall/$', views.sysfirewall, name='sysfirewall'),
    url(r'^serverimprove/$', views.serverimprove, name='serverimprove'),	
    url(r'^servermanage/$', views.servermanage, name='servermanage'),
    url(r'^addserver/$', views.addserver, name='addserver'),
    url(r'^service/$', views.service, name='service'),
    url(r'^buy/$', views.buy, name='buy'),
    url(r'^notice/$', views.notice, name='notice'),
    url(r'^shoppage/$', views.shoppage, name='shoppage'),
    url(r'^signout/$', views.signout, name='signout'),	
    url(r'^actionlog/$', views.actionlog, name='actionlog'),
    url(r'^savesetting/$', views.savechange, name='savechange'),
    url(r'^installsetting/$', views.installsetting, name='installsetting'),

    url(r'^groupset/$', views.groupset, name='groupset'),
    url(r'^setemail/$', views.setemail, name='setemail'),
    url(r'^setphone/$', views.setphone, name='setphone'),
    url(r'^addrule/$', views.saverule, name='saverule'),
    url(r'^delrule/$', views.delrule, name='delrule'),
    url(r'^saveprocess/$', views.saveprocess, name='saveprocess'),
    url(r'^delprocess/$', views.delprocess, name='delprocess'),
    url(r'^processsolution/$', views.processsolution, name='processsolution'),
    url(r'^savewhitelist/$', views.savewhitelist, name='savewhitelist'),
    url(r'^delwhitelist/$', views.delwhitelist, name='delwhitelist'),
    url(r'^savesuperlist/$', views.savesuperlist, name='savesuperlist'),
    url(r'^delsuperlist/$', views.delsuperlist, name='delsuperlist'),
    url(r'^appcontrolsolution/$', views.appcontrolsolution, name='appcontrolsolution'),
    url(r'^outsidecontrolsolution/$', views.outsidecontrolsolution, name='outsidecontrolsolution'),
    url(r'^addportsecurity/$', views.addportsecurity, name='addportsecurity'),
    url(r'^delport/$', views.delport, name='delport'),
    url(r'^portsecuritysolution/$', views.portsecuritysolution, name='portsecuritysolution'),
    url(r'^savecustomgateway/$', views.savecustomgateway, name='savecustomgateway'), 
    url(r'^delcustomgateway/$', views.delcustomgateway, name='delcustomgateway'),
    url(r'^savenetfirewall/$', views.savenetfirewall, name='savenetfirewall'),
    url(r'^saveArpFireWall/$', views.saveArpFireWall, name='saveArpFireWall'),
    url(r'^resetnetfirewall/$', views.resetnetfirewall, name='resetnetfirewall'), 	
    url(r'^saveurlwhitelist/$', views.saveurlwhitelist, name='saveurlwhitelist'), 	
    url(r'^delurlwhitelistid/$', views.delurlwhitelistid, name='delurlwhitelistid'),

    url(r'^savestrategy/$', views.savestrategy, name='savestrategy'),
    url(r'^delstrategy/$', views.delstrategy, name='delstrategy'),
    url(r'^moverserverto/$', views.moverserverto, name='moverserverto'),
	
    url(r'^connectclient/$', views.connectclient, name='connectclient'), 
    url(r'^addremark/$', views.addremark, name='addremark'),
    url(r'^downclient/$', views.downclient, name='downclient'),
    url(r'^groupmanage/$', views.groupmanage, name='groupmanage'),
    url(r'^encryptmsg/$', views.encryptmsg, name='encryptmsg'),

    url(r'^savelog/$', views.savelog, name='savelog'),
    url(r'^savenetworkcount/$', views.savenetworkcount, name='savenetworkcount'),
    url(r'^saveactionlog/$', views.saveactionlog, name='saveactionlog'),
    url(r'^saveusergroup/$', views.saveusergroup, name='saveusergroup'),
    url(r'^saveremotelogin/$', views.saveremotelogin, name='saveremotelogin'),
    url(r'^getnetcount/$', views.getnetcount, name='getnetcount'),
    url(r'^check_code/$', views.check_code, name='check_code'),
    url(r'^maketestdata/$', views.maketestdata, name='maketestdata'),

    url(r'^postversion/$', views.postversion, name='postversion'),
    url(r'^makeclientupdate/$', views.makeclientupdate, name='makeclientupdate'),

    url(r'^serveroptimize/$', views.serveroptimize, name='serveroptimize'),
    url(r'^saveoptimize/$', views.saveoptimize, name='saveoptimize'),
    url(r'^getresult/$', views.getresult, name='getresult'),

    url(r'^saveinterceptip/$', views.saveinterceptip, name='saveinterceptip'),
    url(r'^getremaintime/$', views.getremaintime, name='getremaintime'),
    url(r'^changeinterceptip/$', views.changeinterceptip, name='changeinterceptip'),
    url(r'^delInterceptIP/$', views.delInterceptIP, name='delInterceptIP'),

    url(r'^postserverinfo/$', views.postserverinfo, name='postserverinfo'),

    url(r'^makeclientlinux/$', views.makeclientlinux, name='makeclientlinux'),
    url(r'^register/$', views.register, name='register'),
    url(r'^edit/$', views.edit, name='edit'),

    # url(r'^echo', views.echo, name='echo'),
	
	#client user login
    url(r'^clientlogin/$', views.clientlogin, name='clientlogin'),
    url(r'^clientuninstall/$', views.clientuninstall, name='clientuninstall'),
	
	#save client setting change
    url(r'^onclientchange/$', views.onclientchange, name='onclientchange'),
    url(r'^saverule/$', views.saverule, name='saverule'),
	
    # login / logout urls
    url(r'^login/$', 'django.contrib.auth.views.login', name='login'),
    url(r'^logout/$', 'django.contrib.auth.views.logout', name='logout'),
    url(r'^logout-then-login/$', 'django.contrib.auth.views.logout_then_login', name='logout_then_login'),

    url(r'^passwordchange/$', views.passwordchange, name='passwordchange'),

    # change password urls
    url(r'^password_change/$', 'django.contrib.auth.views.password_change', name='password_change'),
    url(r'^password_change/done/$', 'django.contrib.auth.views.password_change_done', name='password_change_done'),
	
    # url(r'^sendmail/$', views.sendmail, name='sendmail'),
	
    # restore password urls
    url(r'^password-reset/$', 'django.contrib.auth.views.password_reset', name='password_reset'),
    url(r'^password-reset/done/$', 'django.contrib.auth.views.password_reset_done', name='password_reset_done'),
    url(r'^password-reset/confirm/(?P<uidb64>[-\w]+)/(?P<token>[-\w]+)/$', 'django.contrib.auth.views.password_reset_confirm', name='password_reset_confirm'),
    url(r'^password-reset/complete/$', 'django.contrib.auth.views.password_reset_complete', name='password_reset_complete'),

	# # user profiles
    url(r'^users/$', views.user_list, name='user_list'),
    url(r'^users/follow/$', views.user_follow, name='user_follow'),
    url(r'^users/(?P<username>[-\w]+)/$', views.user_detail, name='user_detail'),
    
]
