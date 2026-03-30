using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.SeedData;
using VulnerableIssuerAPI.Services;

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
builder.Services.AddDbContext<VulnerableDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default")));

// Services
builder.Services.AddScoped<AuthorizationService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddScoped<PasswordResetService>();

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

app.MapControllers();

if (app.Environment.IsDevelopment() || args.Contains("--seed"))
{
    await DataSeeder.SeedAsync(app.Services);
}

app.Run();
