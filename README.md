# MHMTSC — Go Native Android Scanner

اپ نیتیو اندروید نوشته‌شده با **Go + Fyne**، اسکن با **raw TCP socket** (بدون TLS handshake)،
که از فیلترینگ DPI/SNI روی پورت 443 رد میشه.

## مراحل push از Termux

```bash
pkg install git -y
cd ~
# این پوشه رو extract کن، بعد:
cd mhmtscanner-go
git init
git add .
git commit -m "init"
git branch -M main
git remote add origin https://github.com/USERNAME/mhmtscanner-go.git
git push -u origin main
```

بعد از push:
- برو گیت‌هاب → تب **Actions**
- صبر کن build تموم بشه (۱۰-۱۵ دقیقه)
- از **Artifacts** فایل `MHMTSC-go-apk` رو دانلود کن
- APK رو از zip دربیار و روی گوشی نصب کن

## چرا Go + raw TCP؟

برخلاف مرورگر (که مجبوره TLS handshake کامل بزنه و DPI شناساییش می‌کنه)،
این اپ با `net.DialTimeout` فقط یه اتصال خام TCP باز می‌کنه —
همون روشی که اسکنرهای نیتیو مثل Rsta Scanner استفاده می‌کنن.
