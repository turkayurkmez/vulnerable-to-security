using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class PasswordResetService
{
    private readonly VulnerableDbContext _context;

    public PasswordResetService(VulnerableDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateResetTokenAsync(string email)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
            return "Hata: Bu email adresi kayıtlı değil";

        var token = $"{user.Id}_{DateTime.Now.Ticks}";

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

        if (resetToken == null) return false;

        resetToken.User.Password = ComputeMd5(newPassword);
        await _context.SaveChangesAsync();

        return true;
    }

    private static string ComputeMd5(string input)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLower();
    }
}
