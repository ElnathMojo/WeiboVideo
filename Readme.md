# 微博视频（秒拍）自动上传脚本
- 用法
    - 传入用户名密码构建Weibo对象
    - 使用login获得或is_login函数载入cookies
    - 使用update_status函数指定视频文件，封面图片，微博内容，视频标题等
  - 其中categorie必填，取值参加网页版微博视频上传处
  - tags为字符串列表

- references
    - 登录脚本 [ShomyLiu/WeiboLogin](https://github.com/ShomyLiu/WeiboLogin)
    - [部分接口说明](http://www.jianshu.com/p/8e03d5f55a21)