using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            _logger.LogInformation(
                "Index page visited at {VisitTime}", 
                DateTime.UtcNow);
            
            await Task.CompletedTask;
            return View();
        }

        public async Task<IActionResult> About()
        {
            _logger.LogInformation(
                "About page visited at {VisitTime}", 
                DateTime.UtcNow);
            
            await Task.CompletedTask;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}