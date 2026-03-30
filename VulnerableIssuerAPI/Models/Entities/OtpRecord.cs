namespace VulnerableIssuerAPI.Models.Entities;

public class OtpRecord
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string OtpCode { get; set; } = string.Empty;
    public string Purpose { get; set; } = "login";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public User User { get; set; } = null!;
}
