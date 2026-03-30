namespace VulnerableIssuerAPI.ThreatModeling
{
    public static class StrideAnalysis
    {
        public record EndpointThreatMap(
            string Endpoint,
            string[] Spoofing,
            string[] Tampering,
            string[] Repudiation,
            string[] InformationDisclosure,
            string[] DenialOfService,
            string[] ElevationOfPrivilege
        );

        public static IEnumerable<EndpointThreatMap> Endpoints => new[]
        {
            new EndpointThreatMap(
                Endpoint:" POST /api/transaction/authorize",
                Spoofing:["S-01 - Authentication yok. Herker erişebilir"],
                Tampering:[
                    "T-01 - Negatif amount verilebiliyor.",
                    "T-02 - Idemptotency sorunu. Aynı istek birden fazla gönderilebilir",
                    "T-03 - XSS Saldırısı mümkün (Açıklama)",
                    "T-04 - Currency bilgisi değişebilir"
                ],
                Repudiation:["R-01 - Loglama yok. Kim ne yapıyor tutulmuyor!"],
                InformationDisclosure:[],
                DenialOfService:["D-01 - DoS saldırısı gelebilir. rate limiting yok!"],
                ElevationOfPrivilege:["E-01 - [Auhorize] attr. olmadığı için yetkisiz işlem açık."]
               )
        };
    }
}
