using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace VulnerableIssuerAPI.Services
{
    public class RsaKeyProvider : IDisposable
    {
        private readonly RSA _rsa = RSA.Create(keySizeInBits: 2048);
        //Biz demo olarak bellekte oluşturuyoruz, gerçek uygulamalarda bu anahtarlar güvenli bir şekilde saklanmalı ve yönetilmelidir.

        public RsaSecurityKey PrivateKey => new RsaSecurityKey(_rsa) { KeyId = "issuer-api-key-v1" };

        public RsaSecurityKey PublicKey
        {
            get
            {
                var publicRsa = RSA.Create();
                publicRsa.ImportRSAPublicKey(_rsa.ExportRSAPublicKey(), out _);
                return new RsaSecurityKey(publicRsa) { KeyId = "issuer-api-key-v1" };
            }
        }
        public void Dispose()
        {
            _rsa.Dispose();
        }

        //JWKS endpoint'i için public key'i JSON formatında döndüren bir yardımcı metot ekleyelim
        public JsonWebKey PublicJwk => JsonWebKeyConverter.ConvertFromRSASecurityKey(PublicKey);
    }
}
