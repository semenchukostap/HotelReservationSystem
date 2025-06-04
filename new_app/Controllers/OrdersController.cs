using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;

namespace new_app.Controllers;

public class OrdersController : Controller
{
    private readonly ApplicationDbContext _context;

    public OrdersController(ApplicationDbContext context)
    {
        _context = context;
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Index()
    {
        return View();
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> New()
    {
        return View();
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Details(int id)
    {
        var order = await _context.Orders
            .Include(o => o.Customer)
            .Include(o => o.Hotel)
                .ThenInclude(h => h.Country)
            .FirstOrDefaultAsync(o => o.Id == id);

        if (order == null)
            return NotFound();

        return View(order);
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        
        if (order == null)
            return NotFound();
            
        _context.Orders.Remove(order);
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(Index));
    }
}