using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/account")]
[Authorize]
public class AccountController : ControllerBase
{
    private readonly VulnerableDbContext _context;

    public AccountController(VulnerableDbContext context)
    {
        _context = context;
    }

    [HttpGet("profile/{userId}")]
    public async Task<IActionResult> GetProfile(int userId)
    {
        var user = await _context.Users
            .Include(u => u.Cards)
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            return NotFound(new { error = "Kullanıcı bulunamadı" });

        return Ok(new
        {
            user.Id,
            user.Username,
            user.Email,
            user.FullName,
            user.Role,
            user.SecurityAnswer,
            Cards = user.Cards.Select(c => new
            {
                c.Id,
                c.CardNumber,
                //c.CVV,
                c.ExpiryMonth,
                c.ExpiryYear,
                c.AvailableBalance
            })
        });
    }

    [HttpGet("cards/{userId}")]
    public async Task<IActionResult> GetUserCards(int userId)
    {
        var cards = await _context.Cards
            .Where(c => c.UserId == userId)
            .ToListAsync();

        return Ok(cards);
    }
}
