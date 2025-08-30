# Gost-MWSS 多服务管理脚本

这是一个用于在 Linux 系统上快速部署和管理多个 Gost MWSS 服务的 Shell 脚本。

## 功能特性

-   **多服务管理**: 轻松添加、删除、启动、停止、重启指定的服务。
-   **状态总览**: 自动列出所有服务的运行状态和开机自启状态。
-   **配置管理**: 支持查看、修改现有服务的配置。
-   **证书管理**:
    -   集成 `acme.sh`，可一键为域名申请免费的 Let's Encrypt 证书。
    -   支持生成自签名证书，方便无域名或测试时使用。
-   **自动更新**: 一键更新 Gost 主程序到最新版本，并可选择自动重启所有服务。
-   **快捷命令**: 可将脚本安装为系统命令 `gost-mwss`，方便随时调用。

## 一键运行

请使用 `root` 用户或有 `sudo` 权限的用户，在终端中执行以下命令：

```bash
wget https://raw.githubusercontent.com/cnnlei/sh/main/gost-mwss.sh
sudo bash gost-mwss.sh
```
