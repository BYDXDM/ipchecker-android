# IP 侦探 (IP Checker) — Android WebView App

一个把本地 IP 全维度检测网页封装成 Android APK 的壳子应用。网页本体在 `app/src/main/assets/web/`。

## 功能
- IP 归属地（IPv4/IPv6）
- IP 纯净度 / 风控评分
- 人机流量对比
- WebRTC 真实 IP 泄露检测
- DNS 泄露检测
- 归属地地图
- 时区时钟

## 构建
Push 到 `main` 分支会自动触发 GitHub Actions 编译 APK，产物为 Release 签名版（自动生成 keystore 签名，可直接安装）。
构建完成后在 Actions 页面的 `ip-detector-apk` artifact 里下载 APK。

## 本地构建（需要 Android Studio / Android SDK）
```bash
# 在项目根目录放一个 keystore.properties（可选，release 签名用）
# storeFile / storePassword / keyAlias / keyPassword

gradle assembleRelease
# 输出: app/build/outputs/apk/release/app-release.apk
```

## 修改网页
直接编辑 `app/src/main/assets/web/` 下的 `index.html` / `style.css` / `app.js`，重新构建即可。
