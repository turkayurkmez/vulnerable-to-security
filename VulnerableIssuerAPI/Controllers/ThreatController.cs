using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VulnerableIssuerAPI.ThreatModeling;

namespace VulnerableIssuerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ThreatController : ControllerBase
    {
        private readonly StrideAnalysisTool strideAnalysis;
        public ThreatController(StrideAnalysisTool strideAnalysis)
        {
            this.strideAnalysis = strideAnalysis;
        }


        //[HttpGet("stride-map")]
        //public IActionResult GetStrideMap()
        //{
        //    return Ok(StrideAnalysis.Endpoints);
        //}

        [HttpGet("summary")]
        public IActionResult GetSummary()
        {
            var model = ThreatMoadelingService.Build();
            var summary = new
            {
                SystemName = model.SystemName,
                Version = model.Version,
                CreatedAt = model.CreatedAt,
                TotalThreats = model.Threats.Count,
                TotalMitigations = model.Mitigations.Count,
                CriticalAndHigh = model.CriticalAndHighPlanned().Select(x => new { x.Id, x.Description, x.Severity, x.CvssScore, Category = x.Category.ToString(), Mitigation = model.GetMitigation(x) is { } m ? new { m.Id, m.Strategy, Status = m.Status.ToString() } : null }),

                ByCategory = Enum.GetValues<StrideCategory>().Select(c => new
                {
                    Category = c.ToString(),
                    Threats = model.GetThreatsByCategory(c).Select(t => new
                    {
                        t.Id,
                        t.CvssScore,
                        Severity = t.Severity.ToString()
                    })
                })

            };
            return Ok(summary);
        }

        [HttpGet("open-risks")]
        public IActionResult GetOpenRisks()
        {
            var risks = strideAnalysis.OpenRisks().Select(r => new
            {
                r.ThreatId,
                r.Category,
                r.Description,
                r.AffectedComponent,
                r.RiskLevel,
                r.MitigationId,
                r.MitigationStatus,
                r.Details,
                Mitigation = new {
                    Id = r.MitigationId,                  
                    Status = r.MitigationStatus.ToString()
                }
            }).ToList();

            return Ok(risks);
        }

    }
}
