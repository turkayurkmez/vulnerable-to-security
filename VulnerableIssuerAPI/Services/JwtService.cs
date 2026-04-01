using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace VulnerableIssuerAPI.Services
{
    public class JwtService(RsaKeyProvider keyProvider, RefreshTokenStore refreshTokenStore)
    {
        private const string Issuer = "issuer-api";
        private const string Audience = "issuer-clients";

        public string GenerateAccessToken(int userId, string role, string scope="full")
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("scope", scope),
                new Claim("userId", userId.ToString())
            };
            var signingCredentials = new SigningCredentials(keyProvider.PrivateKey, SecurityAlgorithms.RsaSha256);
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Issuer = Issuer,
                Audience = Audience,
                Expires = DateTime.UtcNow.AddMinutes(15),
                IssuedAt = DateTime.UtcNow,
                SigningCredentials = signingCredentials
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(descriptor));
        }

        public ClaimsPrincipal? ValidateAccessToken(string token)
        {

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = Audience,
                ValidateLifetime = true,
                IssuerSigningKey = keyProvider.PublicKey,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromSeconds(30),
                ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
            };
            var handler = new JwtSecurityTokenHandler();

            try
            {
                return handler.ValidateToken(token, parameters, out _);
            }
            catch (Exception)
            {

                return null;
            }
            
        }

        public TokenPair GenerateTokenPair(int userId, string role) => new TokenPair( AccessToken: GenerateAccessToken(userId, role), RefreshToken: refreshTokenStore.Create(userId,role) );

        public TokenPair? RefreshToken(string refreshToken)
        {
          var result = refreshTokenStore.Consume(refreshToken);
          if (result == null)
              return null;
          return GenerateTokenPair(result.Value.userId, result.Value.role);
        }
    }

    public record TokenPair(string AccessToken, string RefreshToken);
}
