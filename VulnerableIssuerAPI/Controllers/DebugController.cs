using System.Collections;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("_debug")]
public class DebugController : ControllerBase
{
    private readonly VulnerableDbContext _context;
    private readonly IConfiguration _configuration;

    public DebugController(VulnerableDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        var envVars = new Dictionary<string, string?>();
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            envVars[entry.Key.ToString()!] = entry.Value?.ToString();

        return Ok(new
        {
            Environment = envVars,
            ConnectionString = _configuration.GetConnectionString("Default"),
            MachineName = Environment.MachineName,
            OsVersion = Environment.OSVersion.ToString(),
            DotNetVersion = Environment.Version.ToString(),
            WorkingDirectory = Directory.GetCurrentDirectory(),
            ProcessId = Environment.ProcessId
        });
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users.ToListAsync();
        return Ok(users);
    }

    [HttpGet("health")]
    public IActionResult GetHealth()
    {
        return Ok(new
        {
            Status = "Healthy",
            DatabaseConnected = _context.Database.CanConnect(),
            ConnectionString = _configuration.GetConnectionString("Default"),
            TableCounts = new
            {
                Users = _context.Users.Count(),
                Cards = _context.Cards.Count(),
                Transactions = _context.Transactions.Count(),
                OtpRecords = _context.OtpRecords.Count()
            }
        });
    }

    [HttpPost("execute-sql")]
    public async Task<IActionResult> ExecuteSql([FromBody] string sql)
    {
        try
        {
            var result = await _context.Database.ExecuteSqlRawAsync(sql);
            return Ok(new { AffectedRows = result, ExecutedSql = sql });
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                Error = ex.Message,
                StackTrace = ex.StackTrace,
                InnerException = ex.InnerException?.Message
            });
        }
    }

    [HttpGet("cards")]
    public async Task<IActionResult> GetAllCards()
    {
        var cards = await _context.Cards.ToListAsync();
        return Ok(cards);
    }
}
