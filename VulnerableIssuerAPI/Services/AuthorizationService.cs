using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.Models.StateMachine;

namespace VulnerableIssuerAPI.Services;

public class AuthorizationService
{
    private readonly VulnerableDbContext _context;
    private readonly ILogger<AuthorizationService> _logger;

    private readonly TransactionStateMachine _transactionStateMachine;
    private readonly FraudDetectionService _fraudDetectionService;


    public AuthorizationService(VulnerableDbContext context, ILogger<AuthorizationService> logger, TransactionStateMachine stateMachine, FraudDetectionService fraudDetectionService)
    {
        _context = context;
        _logger = logger;
        _transactionStateMachine = stateMachine;
        _fraudDetectionService = fraudDetectionService;
    }

    public async Task<AuthorizationResponse> PreAuthtorize(AuthorizationRequest request,int requestingUserId )
    {

        if (request.Amount <= 0)
            return new AuthorizationResponse
            {
                IsApproved = false,
            };
       
        var card = await _context.Cards
            .FirstOrDefaultAsync(c => c.CardNumber == request.CardNumber);

        if (card == null)
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = "Kart bulunamadı" };

        if (!_transactionStateMachine.IsOwner(card,requestingUserId))
        {
            _logger.LogWarning("Yetkisiz kart erişimi");
            return new AuthorizationResponse
            {
                IsApproved = false
            };
        }

        if (!card.IsActive)
        {
            return new AuthorizationResponse { IsApproved = false };
        }

        if (_transactionStateMachine.IsCardExpired(card))
        {
            return new AuthorizationResponse { IsApproved = false };
        }



        //if (card.CVV != request.CVV)
        //    return new AuthorizationResponse { IsApproved = false, ErrorMessage = "CVV hatalı" };


        try
        {
            _transactionStateMachine.HoldAmount(card, request.Amount);
        }
        catch (InvalidOperationException ex)
        {

            return new AuthorizationResponse { IsApproved = false };
        }

        // card.AvailableBalance -= request.Amount;
       var result = await _fraudDetectionService.EvaluateAsync(card.CardNumber, request.MerchantId, request.Amount);
        if (result.IsSuspicious)
        {
            _logger.LogWarning("Şüpheli işlem tespit edildi: {Reason}, Card No: {CardNumber}", result.Reason, card.CardNumber[^4..]);
            return new AuthorizationResponse { IsApproved = false, ErrorMessage = result.Reason };
        }



        var txnCount = await _context.Transactions.CountAsync();
        var transactINGuid = Guid.NewGuid().ToString("N");
        var transaction = new Transaction
        {
            TransactionId = $"TXN{transactINGuid}",
            CardId = card.Id,
            MerchantId = request.MerchantId,
            Amount = request.Amount,
            Currency = request.Currency ?? "TRY",
            Status = Models.StateMachine.TransactionStatus.Pending,
            Description = request.Description ?? string.Empty,
            Notes = request.Notes,
            CreatedAt = DateTime.UtcNow,
            AuthorizationCode = $"AUTH{transactINGuid}"
        };

        _transactionStateMachine.EnsureTransition(transaction, TransactionStatus.PreAuthorized);
        transaction.ApplyTransition(TransactionStatus.PreAuthorized);

        _context.Transactions.Add(transaction);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Transaction processed: CardNumber={CardNumber}, Amount={Amount}",
            card.CardNumber, request.Amount);

        return new AuthorizationResponse
        {
            IsApproved = true,
            TransactionId = transaction.TransactionId,
            AuthorizationCode = transaction.AuthorizationCode,
            CardNumber = card.CardNumber,          
            AvailableBalance = card.AvailableBalance,
            RemainingLimit = card.CreditLimit - card.AvailableBalance
        };
    }
}
