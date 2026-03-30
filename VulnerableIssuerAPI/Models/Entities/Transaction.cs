namespace VulnerableIssuerAPI.Models.Entities;

public class Transaction
{
    public int Id { get; set; }
    public string TransactionId { get; set; } = string.Empty;
    public int CardId { get; set; }
    public int MerchantId { get; set; }
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TRY";
    public string Status { get; set; } = "Pending";
    public string Description { get; set; } = string.Empty;
    public string? Notes { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? AuthorizationCode { get; set; }
    public string? FailureReason { get; set; }

    public Card Card { get; set; } = null!;
}
