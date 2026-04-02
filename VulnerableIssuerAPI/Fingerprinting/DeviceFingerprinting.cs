using System.Text;

namespace VulnerableIssuerAPI.Fingerprinting
{
    public record DeviceFingerprinting(string UserAgent, string AcceptLanguage, string? Timezone, string? Platform, bool IsMobileHint)
    {
        public string Hash => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes($"{UserAgent}|{AcceptLanguage}|{Timezone}|{Platform}|{IsMobileHint}")))[..16];
        //ilk 16 karakteri alarak hash'i kısaltıyoruz, bu da çakışma olasılığını artırır ve güvenliği azaltır, ancak performans için tercih edilebilir.

        public static DeviceFingerprinting FromHttpContext(HttpContext context)
        {
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var acceptLanguage = context.Request.Headers["Accept-Language"].ToString();
            var timezone = context.Request.Headers["X-Timezone"].ToString(); //Özel bir header ile timezone bilgisi gönderilebilir
            var platform = context.Request.Headers["Sec-CH-UA-Platform"].ToString(); //Özel bir header ile platform bilgisi gönderilebilir
            var isMobileHint = context.Request.Headers["Sec-CH-UA-Mobile"].ToString() == "?1"; //Basit bir mobil cihaz tespiti
            return new DeviceFingerprinting(userAgent, acceptLanguage, timezone, platform, isMobileHint);
        }

        //stub : Gerçek dünyada, jailbreak tespiti için daha karmaşık yöntemler gerekebilir, ancak bu basit bir örnek olarak düşünülebilir.
        public static bool IsJailBrokenHint(Microsoft.AspNetCore.Http.HttpRequest req)=> 
            req.Headers.TryGetValue("X-Device-Integrity", out var integrity) && integrity == "compromised";



    }
}
