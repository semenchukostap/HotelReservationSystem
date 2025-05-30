using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers
{
    public class ManageController : Controller
    {
        // In ASP.NET Core, User management functionality is handled by Razor Pages
        // Redirecting legacy requests to the new Identity pages
        
        public IActionResult Index()
        {
            return RedirectToPage("/Account/Manage/Index", new { area = "Identity" });
        }

        public IActionResult ChangePassword()
        {
            return RedirectToPage("/Account/Manage/ChangePassword", new { area = "Identity" });
        }

        public IActionResult ManageLogins()
        {
            return RedirectToPage("/Account/Manage/ExternalLogins", new { area = "Identity" });
        }

        // Other redirects can be added as needed to handle old routes
    }
}