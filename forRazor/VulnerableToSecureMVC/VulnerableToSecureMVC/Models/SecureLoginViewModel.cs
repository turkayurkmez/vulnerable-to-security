using System.ComponentModel.DataAnnotations;

namespace VulnerableToSecureMVC.Models
{
    public class SecureLoginViewModel
    {
        [Required(ErrorMessage = "Eposta adresi gereklidir.")]
        [EmailAddress(ErrorMessage = "Geçerli bir eposta adresi giriniz.")]
        [MaxLength(250)]
        public string Email { get; set; }
        [Required(ErrorMessage = "Parola gereklidir.")]
        [MinLength(8, ErrorMessage = "Parola en az 8 karakter olmalıdır.")]
        [MaxLength(100, ErrorMessage = "Parola en fazla 100 karakter olmalıdır.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string? ReturnUrl { get; set; }
    }
}
