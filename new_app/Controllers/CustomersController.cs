using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers;

public class CustomersController : Controller
{
    private readonly ApplicationDbContext _context;

    public CustomersController(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        var customers = await _context.Customers.ToListAsync();
        return View(customers);
    }

    public IActionResult New()
    {
        var customer = new Customer { Name = "" };
        return View("Form", customer);
    }

    public async Task<IActionResult> Edit(int id)
    {
        var customer = await _context.Customers.SingleOrDefaultAsync(c => c.Id == id);

        if (customer == null)
            return NotFound();

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
            _context.Customers.Add(customer);
        else
        {
            var customerInDb = await _context.Customers.SingleAsync(c => c.Id == customer.Id);
            customerInDb.Name = customer.Name;
            customerInDb.Birthdate = customer.Birthdate;
        }

        await _context.SaveChangesAsync();

        return RedirectToAction("Index", "Customers");
    }
}