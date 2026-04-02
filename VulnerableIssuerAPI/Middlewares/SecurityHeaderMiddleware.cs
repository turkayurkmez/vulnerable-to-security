namespace VulnerableIssuerAPI.Middlewares
{
    public class SecurityHeaderMiddleware
    {

        private readonly RequestDelegate next;

        public SecurityHeaderMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public Task InvokeAsync(HttpContext context )
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";// HSTS: HTTPS kullanımını zorunlu kılar  (tarayıcıya en fazla 1 yıl boyunca bu bilgiyi hatırlatır)
               // headers["Content-Security-Policy"] =  "script-src 'self' from-ancestors 'none'"; //CSP: Kaynakların nereden yüklenebileceğini belirler
                headers["Cache-Control"] = "no-store"; //Önbellekleme kontrolü: Hassas verilerin tarayıcı önbelleğinde saklanmasını engeller"]

                headers["Permission-Policy"] = "geolocation=(), microphone=(), camera=()"; //İzin politikası: Tarayıcı özelliklerine erişimi sınırlar

                headers["X-Content-Type-Options"] = "nosniff";
                headers["X-Frame-Options"] = "DENY";
                headers["X-XSS-Protection"] = "1; mode=block";

                return Task.CompletedTask;
            });
            return next(context);

        }
    }
}
