using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

[Authorize]
public class CustomersController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<CustomersController> _logger;

    public CustomersController(
        ApplicationDbContext context,
        ILogger<CustomersController> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<IActionResult> Index()
    {
        var customers = await _context.Customers.ToListAsync();
        return View(customers);
    }

    public IActionResult Create()
    {
        return View("Form", new Customer());
    }

    public async Task<IActionResult> Edit(int id)
    {
        var customer = await _context.Customers.FindAsync(id);
        if (customer == null)
        {
            return NotFound();
        }

        return View("Form", customer);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(Customer customer)
    {
        if (!ModelState.IsValid)
        {
            return View("Form", customer);
        }

        if (customer.Id == 0)
        {
            _context.Customers.Add(customer);
            _logger.LogInformation("New customer created");
        }
        else
        {
            _context.Entry(customer).State = EntityState.Modified;
            _logger.LogInformation("Customer updated: {CustomerId}", customer.Id);
        }

        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }
}