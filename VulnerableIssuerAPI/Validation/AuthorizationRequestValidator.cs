using VulnerableIssuerAPI.Models.DTOs;

namespace VulnerableIssuerAPI.Validation
{

    public record ValidationResult(bool IsValid, IReadOnlyList<string> Errors)
    {
        public static ValidationResult Ok() => new ValidationResult(true, []);
        public static ValidationResult Fail(params string[] errors) => new ValidationResult(false, errors);
    }
    public static class AuthorizationRequestValidator
    {
        public static ValidationResult Validate(AuthorizationRequest request)
        {
            var errors = new List<string>();

            //amount: pozitif ve makul üst sınır:
            if (request.Amount <= 0)
                errors.Add("Miktar sıfırdan büyük olmalıdır.");
            else if (request.Amount > 10000)
                errors.Add("Miktar 10,000 TRY'yi aşamaz.");

            //card-number : 13-19 hane, sadece rakamlar:
            var pan = request.CardNumber?.Replace(" ", "").Replace("-", "") ?? ""; //boşlukları kaldır
            if (pan.Length < 13 || pan.Length > 19 || !pan.All(char.IsDigit))
                errors.Add("Kart numarası 13-19 hane arasında olmalı ve sadece rakamlardan oluşmalıdır.");
            else if (!isValidLuhn(pan))
            {
                errors.Add("Kart numarası geçersiz.");
            }

            //cvv: 3 veya 4 hane, sadece rakamlar:
            if (string.IsNullOrEmpty(request.CVV) || request.CVV.Length < 3 || request.CVV.Length > 4 || !request.CVV.All(char.IsDigit))
                errors.Add("CVV 3 veya 4 hane arasında olmalı ve sadece rakamlardan oluşmalıdır.");

            //currency: geçerli ISO 4217 kodu (örneğin, "TRY", "USD", "EUR"):
            var validCurrencies = new[] { "TRY", "USD", "EUR" };
            if (string.IsNullOrEmpty(request.Currency) || !validCurrencies.Contains(request.Currency))
                errors.Add("Geçersiz para birimi.");

            //Description ve Notes: XSS saldırılarına karşı basit kontrol (örneğin, <script> tag'lerini engelleme):
            if (!string.IsNullOrEmpty(request.Description))
            {
                if (request.Description.Length > 200) errors.Add("Açıklama 200 karakteri geçemez");
                if (request.Description.Contains("<script>", StringComparison.OrdinalIgnoreCase) || request.Description.Contains("</script>", StringComparison.OrdinalIgnoreCase))
                    errors.Add("Açıklama alanında <script> tag'leri kullanılamaz.");

            }

            //Aynı şekilde Notes alanı için de kontrol:
            if (!string.IsNullOrEmpty(request.Notes))
            {
                if (request.Notes.Length > 500) errors.Add("Notlar 500 karakteri geçemez");
                if (request.Notes.Contains("<script>", StringComparison.OrdinalIgnoreCase) || request.Notes.Contains("</script>", StringComparison.OrdinalIgnoreCase))
                    errors.Add("Notlar alanında <script> tag'leri kullanılamaz.");
            }


            return errors.Count == 0 ? ValidationResult.Ok() : ValidationResult.Fail([..errors]);


        }

        private static bool isValidLuhn(string number)
        {
            var sum = 0;
            var odd = true;
            foreach (var c in number)
            {
                int digit = c - '0';
                if (odd) { digit *= 2; if (digit > 9) digit -= 9; }
                sum += digit;
                odd = !odd;
            }

            return sum % 10 == 0;
        }
    }
}
