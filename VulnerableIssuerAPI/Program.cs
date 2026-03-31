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

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidAlgorithms = new[] { "HS256", "HS384", "HS512", "none" },
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret-for-jwt-token-min-128-bit-and-strong-secret!"))
        };
    });

builder.Services.AddAuthorization();


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
        option.Theme =  ScalarTheme.DeepSpace;
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
