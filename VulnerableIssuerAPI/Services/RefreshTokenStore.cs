using System.Security.Cryptography;

namespace VulnerableIssuerAPI.Services
{

    public record RefreshTokenRecord(
        int UserId,
        string Role,
        string TokenHash,
        DateTime ExpiresAt,
        bool IsRevoked
    );
    public class RefreshTokenStore
    {
        private readonly Dictionary<string, RefreshTokenRecord> _store = new();

        private readonly TimeSpan lifeTime = TimeSpan.FromDays(7);

        public string Create(int userId, string role)
        {
            var plain = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace("+", "-")
                                                                                  .Replace("/", "-")
                                                                                  .TrimEnd("=");

            var hash = ComputeHash(plain);

            _store[hash] = new RefreshTokenRecord(userId, role, hash, DateTime.UtcNow.Add(lifeTime), false);

            CleanExpired();
            return plain.ToString();

        }


        public (int userId, string role)? Consume(string plain)
        {
            //Token doğrular, tüketir (rotation), ve (userId ile role) döner.

            var hash = ComputeHash(plain);
            if (!_store.TryGetValue(hash, out var r) || r.IsRevoked || DateTime.UtcNow > r.ExpiresAt)
            {
                _store.Remove(hash);
                return null;

            }

            _store[hash] = r with { IsRevoked = true };
            return (r.UserId, r.Role);

        }

        private void CleanExpired()
        {
            foreach (var key in _store.Where(kv => kv.Value.IsRevoked || DateTime.UtcNow > kv.Value.ExpiresAt).Select(kv => kv.Key))
            {
                _store.Remove(key);
            }
        }

        private string ComputeHash(ReadOnlySpan<char> plain)
        {
            return Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plain.ToString())));
        }
    }
}
