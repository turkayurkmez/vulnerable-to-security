# VulnerableIssuerAPI

Ödeme sistemleri güvenliği eğitimi kapsamında kullanılmak üzere hazırlanmış, kasıtlı güvenlik açıkları içeren bir Issuer API simülasyonudur. Eğitim ortamında açıkların tespit edilmesi, exploit edilmesi ve güvenli alternatiflerin geliştirilmesi amacıyla tasarlanmıştır.

## Kurulum

```bash
git clone <repo-url>
cd VulnerableIssuerAPI
dotnet restore
dotnet ef database update
dotnet run
```

## API Endpoint Listesi

### Auth (`/api/auth`)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/auth/login` | Kullanıcı girişi, JWT token döner |
| POST | `/api/auth/otp/send` | Belirtilen kullanıcı için OTP oluşturur |
| POST | `/api/auth/otp/verify` | OTP doğrulaması yapar |
| POST | `/api/auth/forgot-password` | Şifre sıfırlama token'ı üretir |
| POST | `/api/auth/reset-password` | Token ile şifre sıfırlar |

### Cards (`/api/cards`) — `[Authorize]`

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/api/cards` | Tüm kartları listeler |
| GET | `/api/cards/{id}` | Belirtilen kartın detayını döner |
| GET | `/api/cards/{id}/balance` | Kart bakiye bilgisini döner |

### Transactions (`/api/transactions`)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/transactions/authorize` | Ödeme yetkilendirme işlemi başlatır |
| GET | `/api/transactions` | Tüm işlemleri listeler |
| GET | `/api/transactions/search?query=...` | İşlem arar |
| GET | `/api/transactions/{id}` | Belirtilen işlemin detayını döner `[Authorize]` |

### Account (`/api/account`) — `[Authorize]`

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/api/account/profile/{userId}` | Kullanıcı profil bilgilerini döner |
| GET | `/api/account/cards/{userId}` | Kullanıcıya ait kartları listeler |

### Debug (`/_debug`)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/_debug/info` | Ortam değişkenleri ve sistem bilgisi |
| GET | `/_debug/users` | Tüm kullanıcıları listeler |
| GET | `/_debug/health` | Sağlık kontrolü ve DB bağlantı durumu |
| GET | `/_debug/cards` | Tüm kart verilerini listeler |
| POST | `/_debug/execute-sql` | Gönderilen SQL sorgusunu çalıştırır |

---

## Kapatılan Güvenlik Açıkları

Aşağıda, projede tespit edilen ve düzeltilen güvenlik açıkları listelenmiştir.

### 1. Zayıf Parola Hashleme (MD5 → BCrypt)

| | |
|---|---|
| **Dosya** | `AuthController.cs`, `PasswordResetService.cs` |
| **Önceki Durum** | Parolalar MD5 ile hashleniyordu (`ComputeMd5`). MD5 hızlı ve çarpışma saldırılarına açık bir algoritmadır. |
| **Düzeltme** | `BCrypt.Net.BCrypt.HashPassword` ve `BCrypt.Net.BCrypt.Verify` kullanılarak parola hashleme güçlendirildi. |

### 2. Zayıf JWT İmzalama (HMAC-SHA256 → RSA-SHA256)

| | |
|---|---|
| **Dosya** | `JwtService.cs`, `JwtKeys.cs`, `Program.cs` |
| **Önceki Durum** | JWT token'ları sabit bir secret key ile HMAC-SHA256 kullanılarak imzalanıyordu (`GenerateWeakJwtToken`). Issuer, Audience ve Lifetime doğrulaması yapılmıyordu. |
| **Düzeltme** | RSA-2048 anahtar çifti ile `RS256` algoritması kullanılıyor. Token doğrulamada `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime` ve `ValidAlgorithms` kontrolleri eklendi. `ClockSkew` 30 saniyeye düşürüldü. |

### 3. SQL Injection → Parametreli Sorgular (LINQ)

| | |
|---|---|
| **Dosya** | `TransactionController.cs` — Search endpoint |
| **Önceki Durum** | `FromSqlRaw` ile doğrudan string interpolation kullanılarak SQL sorgusu oluşturuluyordu: `SELECT * FROM Transactions WHERE Description LIKE '%{query}%'` |
| **Düzeltme** | LINQ `.Where()` metodu ile parametreli sorgu kullanılıyor: `.Where(t => t.Description.Contains(query))` |

### 4. IDOR (Insecure Direct Object Reference)

| | |
|---|---|
| **Dosya** | `TransactionController.cs`, `AuthorizationService.cs` |
| **Önceki Durum** | `GetAll` endpoint'i tüm kullanıcıların işlemlerini döndürüyordu. Yetkilendirme sırasında kart sahipliği kontrol edilmiyordu. |
| **Düzeltme** | İşlem listesi JWT'deki `userId` claim'ine göre filtreleniyor. `AuthorizationService` içinde `IsOwner` kontrolü ile kart sahipliği doğrulanıyor. |

### 5. Güvenlik Header'larının Eksikliği

| | |
|---|---|
| **Dosya** | `SecurityHeaderMiddleware.cs` |
| **Önceki Durum** | HTTP yanıtlarında güvenlik header'ları bulunmuyordu. |
| **Düzeltme** | Middleware ile aşağıdaki header'lar eklendi: |

| Header | Değer | Amaç |
|--------|-------|------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTPS kullanımını zorunlu kılar |
| `Cache-Control` | `no-store` | Hassas verilerin önbellekte saklanmasını engeller |
| `Permission-Policy` | `geolocation=(), microphone=(), camera=()` | Tarayıcı özelliklerine erişimi kısıtlar |
| `X-Content-Type-Options` | `nosniff` | MIME type sniffing'i engeller |
| `X-Frame-Options` | `DENY` | Clickjacking saldırılarını engeller |
| `X-XSS-Protection` | `1; mode=block` | Tarayıcı XSS filtresini aktifleştirir |

### 6. Rate Limiting Eksikliği

| | |
|---|---|
| **Dosya** | `Program.cs`, `AuthController.cs` |
| **Önceki Durum** | Şifre sıfırlama endpoint'lerinde istek sınırlaması yoktu; brute-force saldırılarına açıktı. |
| **Düzeltme** | Fixed Window Rate Limiter eklendi: |

| Endpoint | Limit | Pencere |
|----------|-------|---------|
| `forgot-password` | 3 istek | 10 dakika |
| `reset-password` | 5 istek | 15 dakika |

### 7. Tahmin Edilebilir Token → Kriptografik Token

| | |
|---|---|
| **Dosya** | `PasswordResetService.cs` (`TokenGenerator`) |
| **Önceki Durum** | Şifre sıfırlama token'ları tahmin edilebilir yöntemlerle oluşturuluyordu. |
| **Düzeltme** | `RandomNumberGenerator.GetBytes(32)` ile kriptografik olarak güvenli 256-bit token üretimi sağlandı. |

### 8. Token Süre ve Kullanım Kontrolü

| | |
|---|---|
| **Dosya** | `PasswordResetToken.cs`, `PasswordResetService.cs` |
| **Önceki Durum** | Şifre sıfırlama token'larında süre sonu ve kullanım kontrolü yoktu. Token'lar süresiz geçerliydi. |
| **Düzeltme** | `ExpiresAt` alanı ile token süresi sınırlandırıldı. `IsUsed` kontrolü ile tek kullanımlık token mekanizması eklendi. Yeni token oluşturulduğunda eski aktif token'lar geçersiz kılınıyor. |

### 9. Refresh Token Güvenliği

| | |
|---|---|
| **Dosya** | `RefreshTokenStore.cs`, `JwtService.cs` |
| **Önceki Durum** | Refresh token mekanizması yoktu veya güvensizdi. |
| **Düzeltme** | **Token Rotation:** Her kullanımda eski token revoke edilerek yeni token üretiliyor. Token'lar SHA256 ile hashlenerek saklanıyor. Süre sınırı 7 gün. Süresi dolan token'lar otomatik temizleniyor. |

### 10. Input Validation Eksikliği

| | |
|---|---|
| **Dosya** | `AuthorizationRequestValidator.cs` |
| **Önceki Durum** | İşlem yetkilendirme isteklerinde girdi doğrulaması yapılmıyordu. |
| **Düzeltme** | Aşağıdaki doğrulamalar eklendi: |

| Alan | Doğrulama |
|------|-----------|
| Tutar | Pozitif olmalı, 10.000 TRY üst sınırı |
| Kart Numarası | 13-19 hane, sadece rakam, Luhn algoritması kontrolü |
| CVV | 3-4 hane, sadece rakam |
| Para Birimi | ISO 4217 (TRY, USD, EUR) |
| Açıklama / Notlar | Karakter limiti, `<script>` tag engelleme (XSS koruması) |

### 11. Hassas Veri Sızıntısı (Kart Numarası ve CVV Maskeleme)

| | |
|---|---|
| **Dosya** | `TransactionController.cs`, `CardController.cs` |
| **Önceki Durum** | Kart numarası ve CVV bilgileri API yanıtlarında açık metin olarak döndürülüyordu. |
| **Düzeltme** | Kart numaraları maskelendi (`**** **** **** 1234`). CVV bilgisi API yanıtından tamamen çıkarıldı. |

### 12. Device Fingerprinting ve MFA

| | |
|---|---|
| **Dosya** | `DeviceFingerprinting.cs`, `FingerprintingService.cs`, `AuthController.cs` |
| **Önceki Durum** | Farklı cihazlardan giriş yapıldığında ek doğrulama yapılmıyordu. |
| **Düzeltme** | Cihaz parmak izi (User-Agent, Accept-Language, Timezone, Platform) ile SHA256 hash üretiliyor. Yeni cihazdan giriş yapıldığında OTP (MFA) doğrulaması zorunlu tutuluyor. Şüpheli cihazlar (boş User-Agent, jailbreak sinyali) doğrudan engelleniyor. |

### 13. Fraud Detection (Dolandırıcılık Tespiti)

| | |
|---|---|
| **Dosya** | `FraudDetectionService.cs`, `AuthorizationService.cs` |
| **Önceki Durum** | İşlem yetkilendirmesinde dolandırıcılık kontrolü yoktu. |
| **Düzeltme** | Aşağıdaki kontroller eklendi: |

| Kontrol | Açıklama |
|---------|----------|
| Velocity Check | 5 dakikada 5'ten fazla işlem engellenir |
| Blacklisted Merchant | Kara listedeki merchant'ların işlemleri reddedilir |
| Amount Anomaly | Kredi limitinin %80'ini aşan işlemler şüpheli olarak işaretlenir |

### 14. Yetkilendirme ve Rol Tabanlı Erişim

| | |
|---|---|
| **Dosya** | `Program.cs`, `CardController.cs` |
| **Önceki Durum** | Endpoint'lerde yetkilendirme kontrolü yoktu veya yetersizdi. |
| **Düzeltme** | JWT tabanlı authentication aktif edildi. `AdminOnly` ve `UserOnly` politikaları tanımlandı (role + scope claim kontrolü). Hassas endpoint'ler `[Authorize]` attribute ile korunuyor. |

---

## Hâlâ Açık / İyileştirme Bekleyen Konular

> Aşağıdaki maddeler kodda `TODO` olarak işaretlenmiş olup henüz tamamlanmamıştır.

| # | Konu | Dosya |
|---|------|-------|
| 1 | OTP kodu tahmin edilebilir (`Random` → kriptografik RNG kullanılmalı) | `OtpService.cs` |
| 2 | OTP tekrar kullanım kontrolü (kullanıldıktan sonra işaretlenmeli) | `OtpService.cs` |
| 3 | OTP kodu API yanıtında açık metin olarak döndürülüyor | `AuthController.cs` |
| 4 | CORS politikası çok geniş (`AllowAnyOrigin`) | `Program.cs` |
| 5 | Exception handler'da stack trace production'da gizlenmeli | `Program.cs` |
