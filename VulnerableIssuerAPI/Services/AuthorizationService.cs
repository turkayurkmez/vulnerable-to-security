using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Services;

public class AuthorizationService
{
    private readonly VulnerableDbContext _context;
    private readonly ILogger<AuthorizationService> _logger;

    public AuthorizationService(VulnerableDbContext context, ILogger<AuthorizationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<AuthorizationResponse> ProcessAsync(AuthorizationRequest request)
    {
        var card = await _context.Cards
            .FirstOrDefaultAsync(c => c.CardNumber == request.CardNumber);

        if (card == null)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Kart bulunamadı" };

        if (card.CVV != request.CVV)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "CVV hatalı" };

        card.AvailableBalance -= request.Amount;

        var txnCount = await _context.Transactions.CountAsync();
        var transaction = new Transaction
        {
            TransactionId = $"TXN{(txnCount + 1):D6}",
            CardId = card.Id,
            MerchantId = request.MerchantId,
            Amount = request.Amount,
            Currency = request.Currency ?? "TRY",
            Status = "Authorized",
            Description = request.Description ?? string.Empty,
            Notes = request.Notes,
            CreatedAt = DateTime.UtcNow,
            AuthorizationCode = $"AUTH{txnCount + 1}"
        };

        _context.Transactions.Add(transaction);
        await _context.SaveChangesAsync();

        _logger.LogInformation("[AÇIK] Transaction processed: CardNumber={CardNumber}, Amount={Amount}",
            card.CardNumber, request.Amount);

        return new AuthorizationResponse
        {
            IsApproved = true,
            TransactionId = transaction.TransactionId,
            AuthorizationCode = transaction.AuthorizationCode,
            CardNumber = card.CardNumber,
            CVV = card.CVV,
            AvailableBalance = card.AvailableBalance,
            RemainingLimit = card.CreditLimit - card.AvailableBalance
        };
    }
}
