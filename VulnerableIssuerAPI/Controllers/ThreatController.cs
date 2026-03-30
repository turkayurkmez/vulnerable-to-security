using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VulnerableIssuerAPI.ThreatModeling;

namespace VulnerableIssuerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ThreatController : ControllerBase
    {
        [HttpGet("stride-map")]
        public IActionResult GetStrideMap()
        {
            return Ok(StrideAnalysis.Endpoints);
        }
    }
}
