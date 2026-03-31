using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Models.StateMachine
{

    //public class CardBalanceSnapshot
    //{
    //    public int CartId { get; set; }

    //}
    public class TransactionStateMachine
    {
        private readonly ILogger<TransactionStateMachine> _logger;

        public TransactionStateMachine(ILogger<TransactionStateMachine> logger)
        {
            _logger = logger;
        }

        public void EnsureTransition(Transaction transaction, TransactionStatus target)
        {
            if (!TransactionStateMap.IsAllowed(transaction.Status, target))
            {
                throw new InvalidOperationException($"Geçersiz durum geçişi: {transaction.Status} -> {target}. TransactionId:{transaction.TransactionId} ");

            }
        }

        /// <summary>
        /// Pre-auth aşamasında bakiyeden rezerve ederi
        /// </summary>
        /// <param name="card"></param>
        /// <param name="amount"></param>
        public void HoldAmount(Card card, decimal amount)
        {
            if (card.AvailableBalance < amount)
            {
                throw new InvalidOperationException("Yetesiz bakiye");
            }

            card.AvailableBalance -= amount;
            card.HoldBalance += amount;

            _logger.LogInformation($"Hold uygulandı. {card.AvailableBalance} ");
        }


        public void ReleaseHold(Card card, decimal amount)
        {
            //Monitor.Enter(card);
            if (card.HoldBalance < amount)
            {
                throw new InvalidOperationException("Hold yetersiz");
            }

            card.AvailableBalance += amount;
            card.HoldBalance -= amount;
            //Monitor.Exit(card);

            _logger.LogInformation($"Hold release uygulandı. {card.AvailableBalance} ");
        }
        public void Settle(Card card, decimal amount)
        {
            _logger.LogInformation("Settle tamamlandı");
        }

        public bool IsCardExpired(Card card)
        {
            if (!int.TryParse(card.ExpiryYear, out var year) ||
                !int.TryParse(card.ExpiryMonth, out var month))
            {
                return true;
            }

            var expiryDate = new DateTime(2000 + year, month, 1).AddMonths(1).AddDays(1);
            return DateTime.UtcNow.Date > expiryDate;
        }

        public bool IsOwner(Card card, int requestingUserId)
        {
            return card.UserId == requestingUserId;
        }
    }
}
