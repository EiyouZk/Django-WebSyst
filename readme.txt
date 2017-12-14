为了Django-admin的美化，添加Suit2插件，添加了插件之后有了意料之外的事情发生。

因为了suit插件中有自带的password_change_form.html文件，支持Djamgo后台的更改密码页面。在这时，如果因为Django项目中也有PASSWORD_CHANGE url页面跳转的，不知道什么原因，点击前台页面的更改密码的是，可能会跳转到Suit插件的password_change_form.html页面，相当于从一个前台页面直接跳转到了后台的页面，页面风格基调来了个180°大转弯。

这时需要做的是在前台页面中也有添加自己的pass_change_form.html，同时去除Suit插件中password_change_form.html页面，避免跳转错误。

工程名：LeiDunSys

Django工程下的修改密码页面路径：\LeiDunSys\account\templates\registration\  


同时下载下来Suit插件中password_change_form.html文件路径：.\Python27\Lib\site-packages\suit\templates\registration
