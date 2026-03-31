

using VulnerableIssuerAPI.Models.StateMachine;

namespace VulnerableIssuerAPI.Models.Entities;

public class Transaction
{
    public int Id { get; set; }
    public string TransactionId { get; set; } = string.Empty;

    //Transaction enum:
    public TransactionStatus Status { get; set; } = TransactionStatus.Pending;

    public int CardId { get; set; }
    public int MerchantId { get; set; }
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TRY";
    // public string Status { get; set; } = "Pending";
    public string Description { get; set; } = string.Empty;
    public string? Notes { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public string? AuthorizationCode { get; set; }
    public string? DeclineReason { get; set; }

    public Card Card { get; set; } = null!;

    public void ApplyTransition(TransactionStatus newSatus, string? reason = null)
    {
        Status = newSatus;
        UpdatedAt = DateTime.UtcNow;

        if (newSatus == TransactionStatus.Declined)
        {
            DeclineReason = reason;
        }

    }
}
