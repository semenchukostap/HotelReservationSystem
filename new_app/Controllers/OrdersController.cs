using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

public class OrdersController : Controller
{
    private readonly ApplicationDbContext _context;

    public OrdersController(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        var orders = await _context.Orders
            .Include(o => o.Customer)
            .Include(o => o.Hotel)
            .ToListAsync();
            
        return View(orders);
    }

    public async Task<IActionResult> New()
    {
        var customers = await _context.Customers.ToListAsync();
        var hotels = await _context.Hotels.ToListAsync();

        ViewBag.Customers = customers;
        ViewBag.Hotels = hotels;

        return View();
    }

    public async Task<IActionResult> Details(int id)
    {
        var order = await _context.Orders
            .Include(o => o.Customer)
            .Include(o => o.Hotel)
                .ThenInclude(h => h.Country)
            .SingleOrDefaultAsync(o => o.Id == id);

        if (order == null)
            return NotFound();

        return View(order);
    }
}