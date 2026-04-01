using System.Runtime.InteropServices;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.StateMachine;
using VulnerableIssuerAPI.SeedData;
using VulnerableIssuerAPI.Services;
using VulnerableIssuerAPI.ThreatModeling;

var builder = WebApplication.CreateBuilder(args);

var keyProvider = new RsaKeyProvider();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,

            ValidateIssuer = true,
            ValidIssuer = "issuer-api",
            ValidateAudience = true,
            ValidAudience = "issuer-clients",
            ValidateLifetime = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            ClockSkew = TimeSpan.FromSeconds(30),
            IssuerSigningKey = keyProvider.PublicKey
        };

        options.Events = new JwtBearerEvents
        {

            OnChallenge = context =>
            {
                context.HandleResponse(); // Varsayılan 401 yanıtını engelle
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsJsonAsync(new
                {
                    error = "Token doğrulama başarısız. Lütfen geçerli bir token sağlayın."
                });


            },
            OnForbidden = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsJsonAsync(new
                {
                    error = "Erişim reddedildi. Bu kaynağa erişim izniniz yok."
                });
            }
        };
    });

builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin")
                                                  .RequireClaim("scope", "full")

    );

    option.AddPolicy("UserOnly", policy => policy.RequireClaim("role", "user")
                                                 .RequireClaim("scope", "full"));
});




builder.Services.AddRateLimiter(options =>
{
    //options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    //{

    //    //partisyonlama anahtarı olarak IP adresini kullanıyoruz:
    //    var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    //    //ya da user:
    //    //var userId = httpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value ?? "anonymous";

    //    return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
    //    {
    //        PermitLimit = 100,
    //        Window = TimeSpan.FromMinutes(1),
    //        QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
    //        QueueLimit = 0
    //    });



    //});
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin."
        }, cancellationToken);
    };

    options.AddFixedWindowLimiter("forgot-password", limiterOptions =>
    {
        limiterOptions.PermitLimit = 3;
        limiterOptions.Window = TimeSpan.FromMinutes(10);
        limiterOptions.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 0;
    });

    options.AddFixedWindowLimiter("reset-password", limiterOptions =>
    {
        limiterOptions.PermitLimit = 5;
        limiterOptions.Window = TimeSpan.FromMinutes(15);
        limiterOptions.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        limiterOptions.QueueLimit = 0;
    });

});


builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// EF Core + SQLite
builder.Services.AddDbContext<VulnerableDbContext>();

// Services
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddScoped<PasswordResetService>();
builder.Services.AddScoped<TransactionStateMachine>();
builder.Services.AddScoped<StrideAnalysisTool>();
builder.Services.AddScoped<IEmailService, ConsoleEmailService>();
builder.Services.AddScoped<JwtService>();
builder.Services.AddSingleton(keyProvider);
builder.Services.AddSingleton<RefreshTokenStore>();
//builder.Services.AddSingleton<RsaKeyProvider>();


builder.Services.AddControllers();

builder.Services.AddOpenApi();

var app = builder.Build();

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";

        var exceptionFeature = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        if (exceptionFeature != null)
        {
            var ex = exceptionFeature.Error;
            await context.Response.WriteAsJsonAsync(new
            {
                Error = ex.Message,
                StackTrace = ex.StackTrace,
                InnerException = ex.InnerException?.Message,
                Type = ex.GetType().FullName
            });
        }
    });
});

app.UseCors();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(option =>
    {
        option.Title = "VulnerableIssuerAPI — API Reference";
        option.Theme = ScalarTheme.DeepSpace;
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.UseRateLimiter();

app.MapControllers();

if (app.Environment.IsDevelopment())
{
    // await DataSeeder.SeedAsync(app.Services);
    var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<VulnerableDbContext>();
    await dbContext.Database.MigrateAsync();

}

app.Run();
