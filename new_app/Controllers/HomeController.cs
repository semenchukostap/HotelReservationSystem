using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using HotelReservationSystem.Models;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Index page visited at {Time}", DateTime.UtcNow);
            return await Task.FromResult(View());
        }

        public async Task<IActionResult> About()
        {
            _logger.LogInformation("About page visited at {Time}", DateTime.UtcNow);
            return await Task.FromResult(View());
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
