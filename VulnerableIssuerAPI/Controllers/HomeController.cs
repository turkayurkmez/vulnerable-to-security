using Microsoft.AspNetCore.Mvc;

namespace VulnerableIssuerAPI.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
