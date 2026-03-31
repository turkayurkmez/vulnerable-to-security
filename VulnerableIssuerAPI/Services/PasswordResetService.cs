using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class PasswordResetService
{
    private readonly VulnerableDbContext _context;
    private readonly IEmailService _emailService;
    private readonly ILogger<PasswordResetService> _logger;

    public PasswordResetService(VulnerableDbContext context, IEmailService emailService, ILogger<PasswordResetService> logger)
    {
        _context = context;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task<string> GenerateResetTokenAsync(string email)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
            return "Hata: Bu email adresi kayıtlı değil";

        //TODO 2: Tahmin edilebilir token oluşturma yöntemini düzeltin
        var token = TokenGenerator.Generate();

        var resetToken = new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.Now
        };

        _context.PasswordResetTokens.Add(resetToken);
        await _context.SaveChangesAsync();

        return token;
    }

    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        var resetToken = await _context.PasswordResetTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.Token == token);




        if (resetToken == null || (resetToken.IsExpired || resetToken.IsUsed))
        {
            _logger.LogWarning($"Şifre sıfırlama başarısız: Geçersiz veya süresi dolmuş token kullanıldı.");
            return false;
        }

        //TODO 3: MD5 tercih etmeyin, daha güvenli bir hash algoritması kullanın
        resetToken.User.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
        resetToken.IsUsed = true;
        await _context.SaveChangesAsync();

        _logger.LogInformation($"Şifre sıfırlama başarılı: {resetToken.User.Email} adresinin şifresi sıfırlandı.");
        return true;
    }

    public async Task RequestPasswordReset(string email)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
        {
            _logger.LogWarning($"Şifre sıfırlama isteği başarısız: {email} adresi kayıtlı değil.");
            return;
        }
        //Kullanılmış tokenları geçersiz kıl
        foreach (var item in _context.PasswordResetTokens.Where(p => p.UserId == user.Id && !p.IsUsed))
        {
            item.IsUsed = true;
        }

        var token = TokenGenerator.Generate();

        await _context.PasswordResetTokens.AddAsync(new PasswordResetToken
        {
            UserId = user.Id,
            Token = token,
            CreatedAt = DateTime.Now
        });

        await _emailService.SendPasswordResetEmailAsync(user.Email, token);
        _logger.LogInformation($"Şifre sıfırlama isteği başarılı: {email} adresine token gönderildi.");


    }





}

public static class TokenGenerator
{
    internal static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "-").TrimEnd('=');
    }
}

public interface IEmailService
{
    Task SendPasswordResetEmailAsync(string to, string token);
}

public class ConsoleEmailService(ILogger<ConsoleEmailService> logger) : IEmailService
{
    public Task SendPasswordResetEmailAsync(string to, string token)
    {
        logger.LogInformation($"Password reset token for {to}: {token}");
        return Task.CompletedTask;

    }
}
