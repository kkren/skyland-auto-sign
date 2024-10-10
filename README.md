# 森空岛一键签到脚本

> 基于[xxyz30/skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)
> 删除其他调用 支持青龙面板

## 使用方法

### 获取Token

1. 登录[森空岛](https://www.skland.com/)

2. 访问这个网址 https://web-api.skland.com/account/info/hg

   会返回如下信息

   ```json
   {
     "code": 0,
     "data": {
       "content": "Token"
     },
     "msg": "接口会返回您的鹰角网络通行证账号的登录凭证，此凭证可以用于鹰角网络账号系统校验您登录的有效性。泄露登录凭证属于极度危险操作，为了您的账号安全，请勿将此凭证以任何形式告知他人！"
   }
   ```
   data.content即为token

### 青龙面板

1. 添加环境变量

   名称: `SKLAND_TOKEN`

   值: `Token1;Token2;`

   记得添加`;`

2. 在青龙面板的`订阅管理`中点击`新建订阅`，将下方命令参数复制到新建订阅窗口的`名称`中后手动设置定时规则，指定类型为
   `interval` `每 1 天`后点击确定
   ```
    ql repo https://github.com/bwmgd/skyland-auto-sign.git skyland.py "" SecuritySm.py
   ```

3. 安装依赖
   在青龙面板的`依赖管理`中点击`创建依赖`，依赖类型`python3`，自动拆分`是`，名称输入下方命令后，点击确定
   ```
   requests
   cryptography
   ```

4. 默认定时`0 30 8 * * *` , 每天上午8：30运行


