using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;
using VulnerableIssuerAPI.Services;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Http.HttpResults;

namespace VulnerableIssuerAPI.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private const string JwtSecret = "secret-for-jwt-token-min-128-bit-and-strong-secret!";

    private readonly VulnerableDbContext _context;
    private readonly OtpService _otpService;
    private readonly PasswordResetService _passwordResetService;

    public AuthController(VulnerableDbContext context, OtpService otpService, PasswordResetService passwordResetService)
    {
        _context = context;
        _otpService = otpService;
        _passwordResetService = passwordResetService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null)
            return Unauthorized(new { error = "Kullanıcı bulunamadı" });

        var passwordHash = ComputeMd5(request.Password);
        if (user.Password != passwordHash)
            return Unauthorized(new { error = "Şifre hatalı" });

        if (!user.IsActive)
            return Unauthorized(new { error = "Hesap aktif değil" });

        var token = GenerateWeakJwtToken(user);

        return Ok(new LoginResponse
        {
            Token = token,
            UserId = user.Id,
            Username = user.Username,
            Role = user.Role,
            Email = user.Email,
            FullName = user.FullName
        });
    }

    [HttpPost("otp/send")]
    public async Task<IActionResult> SendOtp([FromBody] OtpSendRequest request)
    {
        var user = await _context.Users.FindAsync(request.UserId);
        if (user == null)
            return NotFound(new { error = "Kullanıcı bulunamadı" });

        var otpCode = await _otpService.GenerateOtpAsync(request.UserId, request.Purpose);

        return Ok(new { Message = "OTP gönderildi", OtpCode = otpCode, UserId = request.UserId });
    }

    [HttpPost("otp/verify")]
    public async Task<IActionResult> VerifyOtp([FromBody] OtpVerifyRequest request)
    {
        var isValid = await _otpService.VerifyOtpAsync(request.UserId, request.OtpCode, request.Purpose);

        if (!isValid)
            return BadRequest(new { error = "OTP hatalı veya süresi geçmiş" });

        return Ok(new { Message = "OTP doğrulandı", UserId = request.UserId });
    }

    [HttpPost("forgot-password")]
    [EnableRateLimiting("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        await _passwordResetService.RequestPasswordReset(request.Email);

        //TODO 1: Burada  token'ı e-posta ile gönderilmeli.
        //TODO 4: Rate-limiting uygulanmalı.
        return Ok(new { Message = "Reset token oluşturuldu ve e-posta ile gönderildi" });
    }

    [HttpPost("reset-password")]
    [EnableRateLimiting("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {

        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { error = "Token ve yeni şifre gereklidir" });
        }
        var success = await _passwordResetService.ResetPasswordAsync(request.Token, request.NewPassword);

        if (!success)
            return BadRequest(new { error = "Geçersiz token" });

        return Ok(new { Message = "Şifre başarıyla güncellendi" });
    }

    private static string GenerateWeakJwtToken(User user)
    {
        var key = Encoding.UTF8.GetBytes(JwtSecret);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("userId", user.Id.ToString()),
                new Claim("role", user.Role),
                new Claim("email", user.Email),
                new Claim("balance", "see_account_endpoint")
            }),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static string ComputeMd5(string input)
    {
        var hash = MD5.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLower();
    }
}
