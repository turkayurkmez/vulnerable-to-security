namespace VulnerableIssuerAPI.ThreatModeling
{
    public static class ThreatMoadelingService
    {
        public static ThreatModel Build() => new(
              SystemName: "VulnerableIssuerAPI",
              Version: "1.0",
              CreatedAt: DateTime.UtcNow,
              Threats: BuildThreats(),
              Mitigations: BuildMitigations()

            );

        private static IReadOnlyList<MitigationEntry> BuildMitigations() =>
            [
              new("M-01", MitigationStatus.Planned, "[Authorize] attribute'ü kullanulacak"),
              new("M-02", MitigationStatus.Planned, "Negatif tutar girişi engellenecek"),
            ];


        private static IReadOnlyList<ThreatEntry> BuildThreats() => 
            [
              new("S-01", StrideCategory.Spoofing, SecurityLevel.High,"POST api/transactions/authorize endpoint'i yetkisiz işleme açık", 9.0, "M-01","Saldırgan doğrudan istek gönderir",AffectedComponent:"POST api/transaction/authorize"),

              new("T-01", StrideCategory.Tampering, SecurityLevel.Critical,"Negatif tutar riski", 9, "M-02","Saldırgan negatif tutar girebilir.",AffectedComponent:"POST api/transaction/authorize"),
              

            ];
        
    }
}
