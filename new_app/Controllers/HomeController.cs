using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using new_app.Models;
using System;
using System.Diagnostics;

namespace new_app.Controllers
{
    /// <summary>
    /// Controller for handling home page and general site navigation
    /// </summary>
    [AllowAnonymous]
    public class HomeController(IMemoryCache memoryCache, ILogger<HomeController> logger) : Controller
    {
        private readonly IMemoryCache _memoryCache = memoryCache;
        private readonly ILogger<HomeController> _logger = logger;

        /// <summary>
        /// Displays the home page
        /// </summary>
        /// <returns>The index view</returns>
        // Use ASP.NET Core Response Caching middleware instead of OutputCache attribute
        // This is configured in Program.cs
        [ResponseCache(Duration = 50, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
        public IActionResult Index()
        {
            _logger.LogInformation("Home page accessed at {Time}", DateTime.UtcNow);
            return View();
        }

        /// <summary>
        /// Displays the about page
        /// </summary>
        /// <returns>The about view</returns>
        public IActionResult About()
        {
            _logger.LogInformation("About page accessed at {Time}", DateTime.UtcNow);
            return View();
        }

        /// <summary>
        /// Displays error information
        /// </summary>
        /// <returns>The error view with error details</returns>
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
