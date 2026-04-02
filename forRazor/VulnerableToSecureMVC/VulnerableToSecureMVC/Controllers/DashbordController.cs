using Microsoft.AspNetCore.Mvc;
using VulnerableToSecureMVC.Models;

namespace VulnerableToSecureMVC.Controllers
{
    public class DashbordController : Controller
    {


        [HttpGet]
        public IActionResult Login(string? error = null, string? returnUrl = null)
        {
            ViewBag.Error = error;
            ViewBag.ReturnUrl = returnUrl;
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(SecureLoginViewModel login)
        {
          
            if (!ModelState.IsValid)
            {
                return View(login);
            }

            if (!string.IsNullOrEmpty(login.ReturnUrl) && Url.IsLocalUrl(login.ReturnUrl))
            {
                return Redirect(login.ReturnUrl);
            }
            return View();
        }
    }
}
