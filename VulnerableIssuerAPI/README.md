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
