using VulnerableIssuerAPI.Data;

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
        private static readonly HashSet<int> BlacklistedMerchants = new() { 9999, 8888 };

        public async Task<FraudResult> EvaluateAsync(string cardNumber, int merchantId, decimal amount)
        {
           
        }

    }
}
