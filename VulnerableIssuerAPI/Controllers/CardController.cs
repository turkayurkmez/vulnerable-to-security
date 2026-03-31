using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/cards")]
[Authorize]
public class CardController : ControllerBase
{
    private readonly VulnerableDbContext _context;

    public CardController(VulnerableDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> GetAllCards()
    {
        var cards = await _context.Cards.ToListAsync();
        return Ok(cards);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetCard(int id)
    {
        var card = await _context.Cards.FindAsync(id);

        if (card == null) return NotFound(new { error = "Kart bulunamadı" });

        return Ok(new
        {
            card.Id,
            card.CardNumber,
            //card.CVV,
            card.ExpiryMonth,
            card.ExpiryYear,
            card.CardHolderName,
            card.AvailableBalance,
            card.CreditLimit,
            card.IsActive
        });
    }

    [HttpGet("{id}/balance")]
    public async Task<IActionResult> GetBalance(int id)
    {
        var card = await _context.Cards.FindAsync(id);
        if (card == null) return NotFound();

        return Ok(new
        {
            CardId = card.Id,
            CardNumber = card.CardNumber,
            AvailableBalance = card.AvailableBalance,
            CreditLimit = card.CreditLimit,
            UsedLimit = card.CreditLimit - card.AvailableBalance
        });
    }
}
