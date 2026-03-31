using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Services;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/transactions")]
public class TransactionController : ControllerBase
{
    private readonly VulnerableDbContext _context;
    private readonly AuthorizationService _authorizationService;

    public TransactionController(VulnerableDbContext context, AuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize([FromBody] AuthorizationRequest request, int userId)
    {
        var response = await _authorizationService.PreAuthtorize(request, userId);
        return Ok(response);
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var transactions = await _context.Transactions
            .Include(t => t.Card)
            .ToListAsync();
        return Ok(transactions);
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string query)
    {
        if (string.IsNullOrEmpty(query))
            return BadRequest("Query parametresi gerekli");

        var sql = $"SELECT * FROM Transactions WHERE Description LIKE '%{query}%' OR Notes LIKE '%{query}%'";

        var transactions = await _context.Transactions
            .FromSqlRaw(sql)
            .ToListAsync();

        return Ok(new
        {
            Query = query,
            Count = transactions.Count,
            Results = transactions
        });
    }

    [HttpGet("{id}")]
    [Authorize]
    public async Task<IActionResult> GetTransaction(string id)
    {
        var transaction = await _context.Transactions
            .Include(t => t.Card)
            .FirstOrDefaultAsync(t => t.TransactionId == id);

        if (transaction == null)
            return NotFound(new { error = $"İşlem bulunamadı: {id}" });

        return Ok(transaction);
    }
}
