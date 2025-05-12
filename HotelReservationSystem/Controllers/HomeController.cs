using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        //[ResponseCache(Duration = 50, Location = ResponseCacheLocation.Any, VaryByParam = "*")]
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            return View();
        }
    }
}