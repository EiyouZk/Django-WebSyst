// 打开Web防火墙-规则设置
function Web_firwall_show(level)
{	
	if(0 == level)
	{
		document.getElementById('session_verify_info').innerHTML='该模式对攻击判断较为宽松(正常情况下推荐)';
		document.getElementById('session_verify_juniora').value='初级模式';
	}
	else if(1==level)
	{
		document.getElementById('session_verify_info').innerHTML='该模式对所有访问都会自动验证(网站处于受间歇性攻击情况下推荐)';
		document.getElementById('session_verify_juniora').value='中级模式';
	}
	else if(2==level)
	{
		document.getElementById('session_verify_info').innerHTML='该模式对所有访问都会手动点击验证(网站长期处于受长期攻击的情况下推荐)';
		document.getElementById('session_verify_juniora').value='高级模式';
	}

}


function loadrule()
{
	document.getElementById('titleid').innerHTML='增加文件保护规则';
}

// 判断数组是否包含某个元素
Array.prototype.contains = function (obj)
{
	var i = this.length;
	while (i--) {
		if (this[i] === obj) {
			return true;
		}
	}
	return false;
}

// 移除弹框中高级设置模块中on属性
function removeclass(feature)
{
	$(".tab_menu ul li").removeClass("on");
}