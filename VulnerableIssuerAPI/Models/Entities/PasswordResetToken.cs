namespace VulnerableIssuerAPI.Models.Entities;

public class PasswordResetToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    //TODO 5: Expire yoktu
    DateTime ExpiresAt {  get; set; } = DateTime.UtcNow.AddHours(15);

    public bool IsUsed { get; set; } = false;

    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    public User User { get; set; } = null!;
}
