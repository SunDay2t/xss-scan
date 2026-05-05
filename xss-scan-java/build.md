# XSS-Scan Burp 插件 - Java 版

## 构建

1. 将 Burp Suite 的 JAR 文件（如 `burpsuite_pro.jar` 或 `burpsuite_community.jar`）复制到项目根目录
2. 执行以下命令安装 Burp JAR 到本地 Maven 仓库：

```bash
mvn install:install-file -Dfile=burpsuite_pro.jar -DgroupId=net.portswigger -DartifactId=burp-suite -Dversion=1.0 -Dpackaging=jar
```

3. 取消 `pom.xml` 中依赖的注释，然后构建：

```bash
mvn clean package
```

4. 生成的 JAR 文件在 `target/xss-scan-1.0.0.jar`，加载到 Burp Suite 即可使用

## 功能

- 被动监听 Proxy 流量，自动对参数注入 XSS Payload 检测反射
- 双 Payload 检测：HTML 标签反射（高危）+ 纯文本反射（中危）
- URL 去重：相同路径+参数组合只扫描一次
- 白名单过滤（支持通配符）
- JSON error 字段误报过滤
- 可调节线程数

## 右键菜单

URL 列表右键：
- 复制 URL
- 复制请求包
- 复制响应包
- 发送到 Repeater

请求/响应详情区右键：
- 复制（选中文本或全部内容）
- 复制全部

## 作者

WX: SunDay2__
