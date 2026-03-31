namespace VulnerableIssuerAPI.ThreatModeling
{
    public static class StrideAnalysis
    {
        public record EndpointThreatMap(
            string Endpoint,
            string[] Spoofing,
            string[] Tampering,
            string[] Repudiation,
            string[] InformationDisclosure,
            string[] DenialOfService,
            string[] ElevationOfPrivilege
        );

        public static IEnumerable<EndpointThreatMap> Endpoints => new[]
        {
            // ── TransactionController ──────────────────────────────────────
            new EndpointThreatMap(
                Endpoint:" POST /api/transactions/authorize",
                Spoofing:["S-01 - Authentication yok. Herkes erişebilir"],
                Tampering:[
                    "T-01 - Negatif amount verilebiliyor.",
                    "T-02 - Idempotency sorunu. Aynı istek birden fazla gönderilebilir",
                    "T-03 - XSS Saldırısı mümkün (Description/Notes alanları sanitize edilmiyor)",
                    "T-04 - Currency bilgisi değiştirilebilir"
                ],
                Repudiation:["R-01 - Hassas kart bilgisi loga yazılıyor ama kullanıcı bazlı audit log yok"],
                InformationDisclosure:[
                    "I-01 - Response'da full kart numarası dönüyor (PCI DSS ihlali)",
                    "I-02 - Response'da CVV dönüyor (PCI DSS Req 3.2 ihlali)",
                    "I-03 - Bakiye ve limit bilgisi gereksiz yere açıklanıyor"
                ],
                DenialOfService:["D-01 - Rate limiting yok. DoS saldırısına açık"],
                ElevationOfPrivilege:["E-01 - [Authorize] attr. olmadığı için yetkisiz işlem açık"]
               ),

            new EndpointThreatMap(
                Endpoint:" GET /api/transactions",
                Spoofing:["S-01 - [Authorize] attribute yok. Kimlik doğrulama olmadan erişilebilir"],
                Tampering:[],
                Repudiation:["R-01 - Erişim loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - Tüm işlemler kart detaylarıyla birlikte dönüyor (kullanıcı filtresi yok)",
                    "I-02 - Sayfalama (pagination) yok, tüm veri tek seferde dönüyor"
                ],
                DenialOfService:["D-01 - Pagination yok. Büyük veri setlerinde bellek tükenmesi riski"],
                ElevationOfPrivilege:["E-01 - Herhangi bir kullanıcı tüm işlemleri görebilir"]
               ),

            new EndpointThreatMap(
                Endpoint:" GET /api/transactions/search?query=",
                Spoofing:["S-01 - [Authorize] attribute yok. Kimlik doğrulama olmadan erişilebilir"],
                Tampering:[
                    "T-01 - SQL Injection açığı! FromSqlRaw ile string interpolation kullanılıyor",
                    "T-02 - SQL Injection ile veri değiştirilebilir (UPDATE/DELETE)"
                ],
                Repudiation:["R-01 - Arama sorguları loglanmıyor. Kötü niyetli sorgular izlenemiyor"],
                InformationDisclosure:[
                    "I-01 - SQL Injection ile tüm veritabanı okunabilir",
                    "I-02 - Query parametresi response'da geri dönüyor (reflected input)"
                ],
                DenialOfService:[
                    "D-01 - SQL Injection ile ağır sorgular çalıştırılabilir",
                    "D-02 - Rate limiting yok"
                ],
                ElevationOfPrivilege:[
                    "E-01 - [Authorize] yok, herkes arama yapabilir",
                    "E-02 - SQL Injection ile yetki yükseltme mümkün"
                ]
               ),

            new EndpointThreatMap(
                Endpoint:" GET /api/transactions/{id}",
                Spoofing:["S-01 - JWT doğrulaması zayıf (issuer/audience/lifetime kontrol edilmiyor)"],
                Tampering:[],
                Repudiation:["R-01 - İşlem detayı erişimi loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - IDOR açığı: Herhangi bir kullanıcı herhangi bir işlemi görüntüleyebilir",
                    "I-02 - Kart detayları Include ile birlikte dönüyor"
                ],
                DenialOfService:[],
                ElevationOfPrivilege:["E-01 - Sahiplik kontrolü yok. Başka kullanıcının işlemi görülebilir"]
               ),

            // ── AuthController ─────────────────────────────────────────────
            new EndpointThreatMap(
                Endpoint:" POST /api/auth/login",
                Spoofing:[
                    "S-01 - MD5 ile parola hash'leniyor (rainbow table saldırısına açık)",
                    "S-02 - Brute force koruması yok. Sınırsız deneme yapılabilir"
                ],
                Tampering:[
                    "T-01 - JWT secret kod içinde hardcoded",
                    "T-02 - JWT token'da expiration yok (ValidateLifetime=false)",
                    "T-03 - JWT 'none' algoritması kabul ediliyor (algorithm confusion saldırısı)",
                    "T-04 - JWT issuer/audience doğrulaması kapalı"
                ],
                Repudiation:["R-01 - Başarılı/başarısız giriş denemeleri loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - Farklı hata mesajları ile kullanıcı enumeration mümkün ('Kullanıcı bulunamadı' vs 'Şifre hatalı')",
                    "I-02 - JWT token içinde email ve role gibi hassas bilgiler var"
                ],
                DenialOfService:["D-01 - Rate limiting yok. Brute force ile DoS riski"],
                ElevationOfPrivilege:[
                    "E-01 - JWT 'none' algoritması ile token forge edilebilir",
                    "E-02 - Role claim JWT içinde manipüle edilebilir"
                ]
               ),

            new EndpointThreatMap(
                Endpoint:" POST /api/auth/otp/send",
                Spoofing:["S-01 - Authentication yok. Herhangi bir userId için OTP tetiklenebilir"],
                Tampering:["T-01 - OTP kodu yalnızca 4 haneli (1000-9999), tahmin edilmesi kolay"],
                Repudiation:["R-01 - OTP gönderim işlemi loglanmıyor (Console.WriteLine hariç)"],
                InformationDisclosure:[
                    "I-01 - OTP kodu response body'de döndürülüyor! (SMS/email yerine)",
                    "I-02 - Console.WriteLine ile OTP loga yazılıyor"
                ],
                DenialOfService:["D-01 - Rate limiting yok. OTP flood saldırısı yapılabilir"],
                ElevationOfPrivilege:["E-01 - [Authorize] yok. Herkes herhangi bir kullanıcı için OTP üretebilir"]
               ),

            new EndpointThreatMap(
                Endpoint:" POST /api/auth/otp/verify",
                Spoofing:[
                    "S-01 - OTP süre kontrolü yok. Eski OTP'ler hâlâ geçerli",
                    "S-02 - Brute force koruması yok. 4 haneli OTP denenerek kırılabilir"
                ],
                Tampering:["T-01 - OTP doğrulama sonrası silinmiyor/invalidate edilmiyor (tekrar kullanılabilir)"],
                Repudiation:["R-01 - OTP doğrulama denemeleri loglanmıyor"],
                InformationDisclosure:["I-01 - UserId response'da dönüyor"],
                DenialOfService:["D-01 - Rate limiting yok. Sınırsız doğrulama denemesi yapılabilir"],
                ElevationOfPrivilege:["E-01 - [Authorize] yok. OTP brute force ile kimlik doğrulama bypass edilebilir"]
               ),

            new EndpointThreatMap(
                Endpoint:" POST /api/auth/forgot-password",
                Spoofing:["S-01 - Reset token tahmin edilebilir (userId_DateTimeTicks formatında)"],
                Tampering:["T-01 - Token üretimi kriptografik olarak güvenli değil (GUID/random yerine predictable pattern)"],
                Repudiation:["R-01 - Şifre sıfırlama talepleri loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - Hata mesajı email'in kayıtlı olup olmadığını açığa çıkarıyor (user enumeration)",
                    "I-02 - Reset token doğrudan response'da dönüyor (email yerine)"
                ],
                DenialOfService:["D-01 - Rate limiting yok. Toplu reset token üretilebilir"],
                ElevationOfPrivilege:["E-01 - Tahmin edilebilir token ile başka kullanıcının şifresi sıfırlanabilir"]
               ),

            new EndpointThreatMap(
                Endpoint:" POST /api/auth/reset-password",
                Spoofing:["S-01 - Token süre kontrolü (expiry) yok. Eski token'lar hâlâ geçerli"],
                Tampering:[
                    "T-01 - Token kullanıldıktan sonra silinmiyor (tekrar kullanılabilir)",
                    "T-02 - Yeni şifre MD5 ile hash'leniyor (zayıf algoritma)",
                    "T-03 - Şifre karmaşıklık kontrolü yok (password policy)"
                ],
                Repudiation:["R-01 - Şifre değişiklikleri loglanmıyor"],
                InformationDisclosure:[],
                DenialOfService:["D-01 - Rate limiting yok"],
                ElevationOfPrivilege:["E-01 - Geçerli bir token ile herhangi bir hesabın şifresi değiştirilebilir"]
               ),

            // ── CardController ─────────────────────────────────────────────
            new EndpointThreatMap(
                Endpoint:" GET /api/cards",
                Spoofing:["S-01 - JWT doğrulaması zayıf (issuer/audience/lifetime kontrol edilmiyor, 'none' algoritması kabul ediliyor)"],
                Tampering:[],
                Repudiation:["R-01 - Kart bilgilerine erişim loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - Tüm kartlar dönüyor, kullanıcı bazlı filtreleme yok (IDOR)",
                    "I-02 - Full kart numarası açık şekilde dönüyor (PCI DSS ihlali)",
                    "I-03 - Pagination yok, tüm kart verileri tek seferde dönüyor"
                ],
                DenialOfService:["D-01 - Pagination yok. Büyük veri setinde bellek tükenmesi riski"],
                ElevationOfPrivilege:["E-01 - Herhangi bir authenticated kullanıcı tüm kartları görebilir (rol kontrolü yok)"]
               ),

            new EndpointThreatMap(
                Endpoint:" GET /api/cards/{id}",
                Spoofing:["S-01 - JWT doğrulaması zayıf"],
                Tampering:[],
                Repudiation:["R-01 - Kart detayı erişimi loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - IDOR: Herhangi bir kart ID'si ile başka kullanıcının kartı görülebilir",
                    "I-02 - Full kart numarası ve CVV response'da dönüyor (PCI DSS ihlali)",
                    "I-03 - Bakiye ve limit bilgileri açıklanıyor"
                ],
                DenialOfService:[],
                ElevationOfPrivilege:["E-01 - Sahiplik kontrolü yok. Başka kullanıcının kart bilgilerine erişilebilir"]
               ),

            new EndpointThreatMap(
                Endpoint:" GET /api/cards/{id}/balance",
                Spoofing:["S-01 - JWT doğrulaması zayıf"],
                Tampering:[],
                Repudiation:["R-01 - Bakiye sorgulama loglanmıyor"],
                InformationDisclosure:[
                    "I-01 - IDOR: Herhangi bir kart ID'si ile başka kullanıcının bakiyesi görülebilir",
                    "I-02 - Full kart numarası response'da dönüyor"
                ],
                DenialOfService:[],
                ElevationOfPrivilege:["E-01 - Sahiplik kontrolü yok"]
               ),

            // ── ThreatController ───────────────────────────────────────────
            new EndpointThreatMap(
                Endpoint:" GET /api/threat/stride-map",
                Spoofing:["S-01 - Authentication yok. Herkes erişebilir"],
                Tampering:[],
                Repudiation:["R-01 - Erişim loglanmıyor"],
                InformationDisclosure:["I-01 - İç güvenlik analizi/threat model herkese açık şekilde sunuluyor"],
                DenialOfService:[],
                ElevationOfPrivilege:["E-01 - [Authorize] yok. Saldırgan, sistemdeki açıkları öğrenebilir"]
               ),

            // ── Program.cs (Global) ────────────────────────────────────────
            new EndpointThreatMap(
                Endpoint:" GLOBAL - Program.cs Yapılandırma",
                Spoofing:["S-01 - CORS any origin açık. Herhangi bir domain'den istek kabul ediliyor"],
                Tampering:[
                    "T-01 - JWT ValidateIssuerSigningKey=false, token imza doğrulaması devre dışı",
                    "T-02 - ValidAlgorithms içinde 'none' var, imzasız token kabul ediliyor"
                ],
                Repudiation:[],
                InformationDisclosure:[
                    "I-01 - Exception handler StackTrace ve InnerException bilgisini response'da dönüyor",
                    "I-02 - Exception type bilgisi (FullName) açığa çıkarılıyor"
                ],
                DenialOfService:[],
                ElevationOfPrivilege:["E-01 - Zayıf JWT yapılandırması ile herhangi bir token forge edilebilir"]
               )
        };
    }
}
