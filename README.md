# RXT Config Panel

پنل مدیریت و ساخت کانفیگ RXT، آماده Deploy روی Railway.

## امکانات

- داشبورد مدیریت
- Login امن با JWT و bcrypt
- مدیریت کاربران
- ساخت کانفیگ
- VLESS
- VMess
- Trojan
- Shadowsocks
- WireGuard
- QR Code
- لینک Subscription برای هر کاربر
- مدیریت Node/Server
- حجم، مصرف، تاریخ انقضا و تعداد دستگاه
- PostgreSQL
- Docker
- Railway Healthcheck
- رابط فارسی و RTL

## معماری

این پروژه یک سرویس Node.js/Express است که UI را نیز از همان سرویس ارائه می‌کند. بنابراین برای Railway فقط یک Web Service لازم است؛ دیتابیس PostgreSQL را به‌صورت جداگانه به پروژه Railway اضافه کنید.

Railway برای سرویس‌های GitHub می‌تواند با Dockerfile موجود در ریشه پروژه build کند. همچنین PostgreSQL متغیر `DATABASE_URL` در اختیار سرویس قرار می‌دهد.

## اجرای محلی

```bash
cp .env.example .env
npm install
npm start
```

سپس:
`http://localhost:3000`

برای اولین ورود، `ADMIN_USERNAME` و `ADMIN_PASSWORD` را از `.env` می‌خواند.

## Deploy روی Railway

1. Repository را به GitHub Push کنید.
2. در Railway یک Project بسازید.
3. یک PostgreSQL Service اضافه کنید.
4. Repository را به‌عنوان Web Service متصل کنید.
5. در Variables سرویس، `DATABASE_URL` را به `DATABASE_URL` سرویس PostgreSQL reference کنید.
6. `JWT_SECRET`، `ADMIN_USERNAME` و `ADMIN_PASSWORD` را تنظیم کنید.
7. Deploy کنید.
8. از Settings → Networking یک Domain بسازید.

Healthcheck:
`/api/health`

## نکته مهم درباره VPN

این پروژه «پنل مدیریت و تولید کانفیگ» است و خودش ترافیک VPN را عبور نمی‌دهد. برای اتصال واقعی کانفیگ‌ها به Xray/WireGuard باید Nodeهای VPN واقعی خارج از Railway داشته باشید و در مرحله بعد یک Node Agent/API امن به پنل اضافه شود.

## مجوز

MIT
