# دیده‌بان ترافیک (Traffic Monitor)

اپ اندروید شخصی برای ثبت و کنترل کامل ترافیک شبکه. بدون نیاز به root.

## وضعیت نسخه ۱.۰ (پایه فنی)

این نسخه **زیرساخت کامل** (VPN، پارسرها، UI، لاگ، فایروال) را شامل می‌شود
و می‌توان آن را بیلد و نصب کرد. سه بخش زیر به‌صورت «نیمه‌کامل» پیاده‌سازی
شده‌اند و در نسخه‌های بعدی تکمیل می‌شوند (توضیح داده شده که کجا ناقصند):

### پیاده‌سازی شده و کارکردنده
- VpnService پایدار با MTU ۱۴۰۰، نوتیفیکیشن فورگراند، شروع خودکار بعد بوت
- پارسرهای کامل: IPv4/IPv6، TCP، UDP، DNS، TLS SNI، HTTP
- بیلدر دست‌نویس پکت TCP/IP با چک‌سام درست (SYN-ACK, ACK, RST, FIN)
- رله UDP کامل با سوکت‌های محافظت‌شده (protect)
- مدل داده، دیتابیس SQLite، بافر لاگ، فلاش دوره‌ای
- موتور فایروال با قوانین اپ/دامنه و الگوی `*`
- UI کامل فارسی RTL: داشبورد، اپ‌ها، لاگ زنده، تنظیمات
- نگاشت UID به نام اپ، کش، نمایش ترافیک ۲۴ ساعت اخیر

### نیمه‌کامل (نیاز به تکمیل در v1.1)
1. **رله TCP کامل**: در نسخه فعلی پکت‌های TCP فقط لاگ و فایروال می‌شوند
   ولی یک TCP Proxy در فضای کاربر (مثل NetGuard) ساخته نشده. یعنی اگر
   فایروال مسدود نکرد، ترافیک عبور می‌کند؛ اما بستن یک اتصال TCP فقط با
   پکت RST ساده کافی نیست — باید یک userspace TCP stack (یا از TUN مستقیم)
   استفاده شود.
2. **نگاشت UID دقیق**: در حال حاضر همه اتصالات UID ۰ دریافت می‌کنند. برای
   نسخه‌های اندروید ۹+ باید از `ConnectivityManager.getConnectionOwnerUid()`
   استفاده شود (یا از `/proc/net` خواندن).
3. **محتوای واقعی HTTPS**: بدون root، بدنه HTTPS قابل مشاهده نیست. برای
   مشاهده آن یا باید گواهی CA در سیستم نصب شود (نیاز به دسترسی سیستم/root)
   یا فقط ترافیک HTTP نمایش داده شود. در حال حاضر: SNI + دامنه + گواهی
   برای HTTPS، و محتوای کامل برای HTTP.

### محدودیت‌های قابل قبول (بدون root)
- حجم اتصالات از `TrafficStats` تخمین زده می‌شود (تقریباً، نه دقیق بایتی)
- اپ‌هایی که از سوکت‌های مستقیم هسته استفاده می‌کنند (مثل بعضی اپ‌های VPN)
  قابل مشاهده نیستند

## ساختار پروژه

```
app/src/main/java/ir/trafficmonitor/app/
├── App.kt                      # اپ و دیتابیس
├── model/                      # ConnectionRecord, HttpInfo, AppTraffic, FirewallRule
├── net/                        # RawPacket, TcpPacketBuilder, TlsParser, DnsParser, HttpParser
├── vpn/                        # TrafficVpnService, ConnectionTracker, UdpRelay, VpnManager
├── db/                         # AppDatabase, LogStore
├── firewall/                   # FirewallEngine
├── prefs/                      # SettingsStore
├── ui/                         # MainActivity, DashboardFragment, AppsFragment, LogFragment, SettingsFragment
└── util/                       # AppResolver, FormatUtils
```

## بیلد

```bash
cd traffic-monitor
./gradlew assembleDebug
```

خروجی: `app/build/outputs/apk/debug/app-debug.apk`

## مجوزهای مورد نیاز

- `BIND_VPN_SERVICE`: فقط قابل فعال‌سازی توسط کاربر (دیالوگ سیستمی اندروید)
- `INTERNET`, `ACCESS_NETWORK_STATE`: برای پکت‌های خروجی
- `POST_NOTIFICATIONS`: برای نوتیفیکشن فورگراند (اندروید ۱۳+)
- `QUERY_ALL_PACKAGES`: برای فهرست اپ‌های دارای اینترنت
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`: برای سرویس پس‌زمینه
- `RECEIVE_BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`: شروع خودکار

## حریم خصوصی

- تمام داده‌ها فقط در SQLite محلی گوشی ذخیره می‌شوند
- هیچ سرویت backend خارجی وجود ندارد
- ترافیک از طریق VPN محلی عبور می‌کند (سرور خارجی ندارد)
- خروجی لاگ: فقط به صورت CSV/JSON توسط کاربر (در نسخه‌های بعد)
