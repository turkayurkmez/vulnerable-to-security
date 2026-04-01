namespace VulnerableIssuerAPI.Models.Entities;

public class OtpRecord
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string OtpCode { get; set; } = string.Empty;
    public string Purpose { get; set; } = "login";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public User User { get; set; } = null!;
    /*
     * TODO 6.3: OTP IsUsed, ExpiredAt, MaxAttempts, AttemptCount gibi alanlar ekleyerek OTP doğrulama sürecini daha güvenli hale getirin.
     */


}

public static class OtpGenerator
{
    public static string GenerateOtp()
    {
        return System.Security.Cryptography.RandomNumberGenerator.GetInt32(100_000, 1_000_000).ToString();

    }
}
