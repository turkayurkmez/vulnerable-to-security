namespace VulnerableIssuerAPI.ThreatModeling
{


    public record DreadDimensions(
        int DamagePotential, // Hasar büyüklüğü
        int Reproducibility, // Saldırının tekrarlanabilirliği
        int Exploitability, // Saldırının gerçekleştirilebilirliğinin kolaylığı
        int AffectedUsers, // Etkilenen kullanıcı sayısı veya oranı
        int Discoverability // Saldırının keşfedilebilirliği
    )
    {
        public void Validate()
        {
            static void CheckRange(int value, string name)
            {
                if (value < 1 || value > 10)
                    throw new ArgumentOutOfRangeException(name, $"{name} değeri 1 ile 10 arasında olmalıdır.");
            }

            CheckRange(DamagePotential, nameof(DamagePotential));
            CheckRange(Reproducibility, nameof(Reproducibility));
            CheckRange(Exploitability, nameof(Exploitability));
            CheckRange(AffectedUsers, nameof(AffectedUsers));
            CheckRange(Discoverability, nameof(Discoverability));
        }
    };

    public enum DreadRiskLevel
    {
        Low, // Düşük risk: 0.1-3.9 arası toplam puan
        Medium, // Orta risk: 4.0-6.9 arası toplam puan
        High, // Yüksek risk: 7.0-8.9 arası toplam puan,
        Critical // Kritik risk 9.0-10.0 puan
    }

    public record DreadScore(string ThreadId, DreadDimensions Dimensions, string MitigationId)
    {

        public double InherentRiskScore => (Dimensions.DamagePotential + Dimensions.Reproducibility + Dimensions.Exploitability + Dimensions.AffectedUsers + Dimensions.Discoverability) / 5.0;

        public DreadRiskLevel RiskLevel => InherentRiskScore switch
        {
            >= 9.0 => DreadRiskLevel.Critical,
            >= 7.0 => DreadRiskLevel.High,
            >= 4.0 => DreadRiskLevel.Medium,
            _ => DreadRiskLevel.Low
        };

        // mitigation'un Hafifletme durumuna göre etkisi
        public static double EffectivenessOf(MitigationStatus status) => status switch
        {
            MitigationStatus.Open => 0.0,
            MitigationStatus.Planned => 0.1,
            MitigationStatus.Implemented => 0.7,
            MitigationStatus.Verified => 0.9,
            _ => 0.0
        };


        public double ResidualRiskScore(MitigationStatus mitigationStatus)=>
            Math.Round(InherentRiskScore * (1 - EffectivenessOf(mitigationStatus)), 2);

        public DreadRiskLevel ResidualRiskLevel(MitigationStatus mitigationStatus)
        {
            var residualScore = ResidualRiskScore(mitigationStatus);
            return residualScore switch
            {
                >= 9.0 => DreadRiskLevel.Critical,
                >= 7.0 => DreadRiskLevel.High,
                >= 4.0 => DreadRiskLevel.Medium,
                _ => DreadRiskLevel.Low
            };
        }

    }
    public class RiskScore
    {

    }
}
