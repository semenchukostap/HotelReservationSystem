using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using new_app.Models;
using System.Diagnostics;

namespace new_app.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<HomeController> _logger;

        public HomeController(IMemoryCache memoryCache, ILogger<HomeController> logger)
        {
            _memoryCache = memoryCache;
            _logger = logger;
        }

        // Use ASP.NET Core Response Caching middleware instead of OutputCache attribute
        // This is configured in Program.cs
        [ResponseCache(Duration = 50, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
