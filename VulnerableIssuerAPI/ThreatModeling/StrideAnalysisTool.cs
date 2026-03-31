using static VulnerableIssuerAPI.ThreatModeling.StrideAnalysisTool;

namespace VulnerableIssuerAPI.ThreatModeling
{
    public class StrideAnalysisTool
    {
        private readonly ThreatModel _model;

        private readonly IReadOnlyDictionary<string, DreadScore> _score;

        public StrideAnalysisTool()
        {
            _model = ThreatMoadelingService.Build();
            _score = BuildScores();
        }

        private IReadOnlyDictionary<string, DreadScore>? BuildScores() => new[]
        {
            new DreadScore
            (
                ThreadId: "S-01",
                Dimensions: new DreadDimensions
                (
                    DamagePotential:8,
                    Reproducibility: 9,
                    Exploitability: 7,
                    AffectedUsers: 6,
                    Discoverability: 8
                ),
                MitigationId : "M1"
            )

        }.ToDictionary(s => s.ThreadId);


        public record ScoredThreat(
            string ThreatId,
            string Category,
            string Description,
            string AffectedComponent,
            DreadDimensions? Dimensions,
            double? InherentRiskScore,
            string RiskLevel,
            string MitigationId,
            MitigationStatus MitigationStatus,
            string? Details,
            double ResidualRiskScore,
            string ResidualRiskLevel
            );

        public record MitigationPlanEntry(
            IReadOnlyList<string> Mitigations,
            IReadOnlyList<string> AffectThreats,
            double CurrentResidualRisk,
            double ProjectedResidualRisk,
            double RiskReduction

            );

        public IEnumerable<ScoredThreat> ScoreAll() => _model.Threats.Select(BuildScoredThreat);

        private ScoredThreat BuildScoredThreat(ThreatEntry threat)
        {
            var mitigation = _model.GetMitigation(threat);
            var score = _score.GetValueOrDefault(threat.Id);
            var status = mitigation?.Status ?? MitigationStatus.Open;
            var inherent = score?.InherentRiskScore ?? 0.0;
            var residual = score?.ResidualRiskScore(status) ?? inherent;

            var riskLevel = score?.RiskLevel ?? DreadRiskLevel.Low;
            var residualRiskLevel = score?.ResidualRiskLevel(status) ?? DreadRiskLevel.Low;


            return new ScoredThreat
            (
                ThreatId: threat.Id,
                Category: threat.Category.ToString(),
                Description: threat.Description,
                AffectedComponent: threat.AffectedComponent ?? "Unknown",
                Dimensions: score?.Dimensions,
                InherentRiskScore: inherent,
                RiskLevel: riskLevel.ToString(),
                MitigationId: threat.MitigationId,
                MitigationStatus: status,
                Details: score != null ? $"Mitigation status: {status}, inherent risk: {inherent}, residual risk: {residual}" : null,
                ResidualRiskScore: residual,
                ResidualRiskLevel: residualRiskLevel.ToString()
            );

        }

        public IEnumerable<ScoredThreat> OpenRisks() => ScoreAll().Where(t => t.MitigationStatus == MitigationStatus.Open || t.MitigationStatus == MitigationStatus.Planned);

        public record AnalysisReport(
          string SystemName,
         DateTime CreatedAt,
         int TotalThreats,
        int OpenThreatsCount,
        double TotalInherentRisk,
        double TotalResidualRisk,
     IReadOnlyList<ScoredThreat> Threats
     );

        public AnalysisReport GenerateReport()
        {
            var scoredThreats = ScoreAll().ToList();
            return new AnalysisReport
            (
                SystemName: _model.SystemName,
                CreatedAt: DateTime.UtcNow,
                TotalThreats: scoredThreats.Count,
                OpenThreatsCount: scoredThreats.Count(t => t.MitigationStatus == MitigationStatus.Open || t.MitigationStatus == MitigationStatus.Planned),
                TotalInherentRisk: scoredThreats.Sum(t => t.InherentRiskScore ?? 0.0),
                TotalResidualRisk: scoredThreats.Sum(t => t.ResidualRiskScore),
                Threats: scoredThreats
            );
        }
    }


}
