namespace VulnerableIssuerAPI.Models.Entities;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "customer";
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? SecurityAnswer { get; set; }

    public ICollection<Card> Cards { get; set; } = new List<Card>();
    public ICollection<OtpRecord> OtpRecords { get; set; } = new List<OtpRecord>();
    public ICollection<PasswordResetToken> PasswordResetTokens { get; set; } = new List<PasswordResetToken>();
}
