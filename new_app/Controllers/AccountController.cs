using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers
{
    public class AccountController : Controller
    {
        // In ASP.NET Core, Identity functionality is handled by Razor Pages
        // Redirecting legacy requests to the new Identity pages
        
        public IActionResult Login(string returnUrl = null)
        {
            return RedirectToPage("/Account/Login", new { area = "Identity", returnUrl });
        }

        public IActionResult Register(string returnUrl = null)
        {
            return RedirectToPage("/Account/Register", new { area = "Identity", returnUrl });
        }

        public IActionResult ForgotPassword()
        {
            return RedirectToPage("/Account/ForgotPassword", new { area = "Identity" });
        }

        // Other redirects can be added as needed to handle old routes
    }
}