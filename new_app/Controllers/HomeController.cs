using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using new_app.Models;
using System.Diagnostics;
using System.Threading.Tasks;

namespace new_app.Controllers;

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
        _logger.LogInformation("Index page accessed");
        return View();
    }

    public async Task<IActionResult> About()
    {
        _logger.LogInformation("About page accessed");
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        var errorModel = new ErrorViewModel 
        { 
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier 
        };
        
        _logger.LogError("Error page accessed with RequestId: {RequestId}", errorModel.RequestId);
        return View(errorModel);
    }
}