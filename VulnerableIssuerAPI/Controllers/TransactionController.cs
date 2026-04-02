using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.Services;
using VulnerableIssuerAPI.Validation;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/transactions")]
//[Authorize]
public class TransactionController : ControllerBase
{
    private readonly VulnerableDbContext _context;
    private readonly AuthorizationService _authorizationService;

    public TransactionController(VulnerableDbContext context, AuthorizationService authorizationService)
    {
        _context = context;
        _authorizationService = authorizationService;
    }

    [HttpDelete]
    public async Task<IActionResult> Remove()
    {
        var upsatedTransaction = new Transaction { Id = 4, Amount = 150, CardId = 3, TransactionId = "TX000004", UpdatedAt = DateTime.UtcNow.AddDays(-3) };
        _context.Transactions.Update(upsatedTransaction);


        await _context.SaveChangesAsync();
        return NoContent();
        ;
    }

    [HttpPost("authorize")]
    public async Task<IActionResult> Authorize([FromBody] AuthorizationRequest request, int userId)
    {
        var valid = AuthorizationRequestValidator.Validate(request);
        if (!valid.IsValid)
            return BadRequest(new { errors = valid.Errors });


        var response = await _authorizationService.PreAuthtorize(request, userId);

        if (!response.IsApproved)
        {
            return BadRequest(new { error = response.ErrorMessage });

        }

        return Ok(new
        {
            response.TransactionId,
            response.AuthorizationCode,
            Last4Digity = "**** **** **** " + response.CardNumber.Substring(response.CardNumber.Length - 4),
            response.AvailableBalance

        });
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        //DİKKAT: IDOR açığına neden olabilir, gerçek uygulamalarda kullanıcıya özel veriler döndürülmelidir
        //var transactions = await _context.Transactions
        //    .Include(t => t.Card)
        //    .ToListAsync();
        //return Ok(transactions);

        var userId = User.FindFirstValue("userId") ?? "0";

        var transactions = await _context.Transactions
                                         .Include(t => t.Card)
                                         .Where(t=>t.Card.UserId == int.Parse(userId)) 
                                         .OrderByDescending(t => t.CreatedAt)
                                         .Take(100)
                                         .Select(Card => new
                                         {
                                             Card.TransactionId,
                                             Card.Amount,
                                             Card.Currency,
                                             Card.Description,
                                             Card.Notes,
                                             Card.CreatedAt,
                                             MaskedCardNumber = "**** **** **** " + Card.Card.CardNumber.Substring(Card.Card.CardNumber.Length - 4)
                                         })
                                         .ToListAsync();

        return Ok(transactions);
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string query)
    {
        if (string.IsNullOrEmpty(query))
            return BadRequest("Query parametresi gerekli");


        //   var sql = $"SELECT * FROM Transactions WHERE Description LIKE '%{query}%' OR Notes LIKE '%{query}%'";

        //var transactions = await _context.Transactions
        //    .FromSqlRaw(sql)
        //    .ToListAsync();

        var transactions = await _context.Transactions
                                         .Include(t => t.Card)
                                         .Where(t => t.Description.Contains(query) || (t.Notes != null && t.Notes.Contains(query)))
                                         .OrderByDescending(t => t.CreatedAt)
                                         .Take(50)
                                         .Select(Card => new
                                         {
                                             Card.TransactionId,
                                             Card.Amount,
                                             Card.Currency,
                                             Card.Description,
                                             Card.Notes,
                                             Card.CreatedAt,
                                             MaskedCardNumber = "**** **** **** " + Card.Card.CardNumber.Substring(Card.Card.CardNumber.Length - 4)
                                         })
                                         .ToListAsync();



        return Ok(new
        {
            Count = transactions.Count,
            Results = transactions
        });
    }

    [HttpGet("{id}")]
    [Authorize]
    public async Task<IActionResult> GetTransaction(string id)
    {
        //Başkasının işlem detaylarına erişim engellenmeli, gerçek uygulamalarda kullanıcıya özel veriler döndürülmelidir
        var transaction = await _context.Transactions
            .Include(t => t.Card)
            .FirstOrDefaultAsync(t => t.TransactionId == id);

        if (transaction == null)
            return NotFound(new { error = $"İşlem bulunamadı: {id}" });

        return Ok(transaction);
    }


}
