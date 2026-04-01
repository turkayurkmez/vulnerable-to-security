using VulnerableIssuerAPI.Data;
using Microsoft.EntityFrameworkCore;
namespace VulnerableIssuerAPI.Services
{

    public record FraudResult(
        bool IsSuspicious,
        string Reason
    );
    public class FraudDetectionService(VulnerableDbContext dbContext, ILogger<FraudDetectionService> logger)
    {

        //Velocity check: 5 dakikada 5 işlemden fazla

        private const int VelocityWindowMinutes = 5;
        private const int VelocityMaxCount = 5;

        //Kara listedek Merchant kontrolü
        //normalde bu tür veriler db'den çekilir, ancak basitlik açısından hardcoded olarak tanımlanmıştır.
        private static readonly HashSet<int> BlacklistedMerchants = new() { 9999, 8888 };

        public async Task<FraudResult> EvaluateAsync(string cardNumber, int merchantId, decimal amount)
        {
            if (BlacklistedMerchants.Contains(merchantId))
            {
                logger.LogWarning("Bu merchant kara listede");
                return new FraudResult(true, "Bu merchant kara listede");
            }

            var card = await dbContext.Cards.FirstOrDefaultAsync(c => c.CardNumber == cardNumber);
            if (card == null)
            {
                logger.LogWarning("Kart bulunamadı");
                return new FraudResult(false, "Kart bulunamadı");
            }


            var since  = DateTime.UtcNow.AddMinutes(-VelocityWindowMinutes);
            var recentTransactionsCount = await dbContext.Transactions
                .Where(t => t.CardId == card.Id && t.CreatedAt >= since)
                .CountAsync();

            if (recentTransactionsCount >= VelocityMaxCount)
            {
                logger.LogWarning("Kartın işlem hızı sınırı aşıldı");
                return new FraudResult(true, "Kartın işlem hızı sınırı aşıldı");
            }

            //3. Amount anomaly check: 1000 TL üzeri işlemler şüpheli olarak işaretlenir
            if (card.CreditLimit > 0 && amount > card.CreditLimit * 0.8m)
            {
                logger.LogWarning("İşlem tutarı anormal");
                return new FraudResult(true, "İşlem tutarı anormal");
            }

            return new FraudResult(false, "İşlem normal");
        }

    }
}
