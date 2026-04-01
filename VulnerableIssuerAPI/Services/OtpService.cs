using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class OtpService
{
    private readonly VulnerableDbContext _context;

    public OtpService(VulnerableDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateOtpAsync(int userId, string purpose)
    {
        var random = new Random();
        //TODO 6.2: Tahmin edilebilir OTP kodu oluşturma yöntemini düzeltin (örneğin, kriptografik olarak güvenli rastgele sayı üreteci kullanarak).
        var otpCode = random.Next(1000, 9999).ToString();

        var otpRecord = new OtpRecord
        {
            UserId = userId,
            OtpCode = otpCode,
            Purpose = purpose,
            CreatedAt = DateTime.UtcNow
        };

        _context.OtpRecords.Add(otpRecord);
        await _context.SaveChangesAsync();

        Console.WriteLine($"[DEBUG] OTP generated for userId={userId}: {otpCode}");

        return otpCode;
    }

    public async Task<bool> VerifyOtpAsync(int userId, string otpCode, string purpose)
    {
        //TODO 6.3: aynı OTP code'u tekrar çalıştırılabilir. Bu nedenle, db'de işareletnmeli.
        var otp = await _context.OtpRecords
            .Where(o => o.UserId == userId
                     && o.OtpCode == otpCode
                     && o.Purpose == purpose)
            .FirstOrDefaultAsync();

        if (otp == null) return false;

        return true;
    }
}
