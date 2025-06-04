using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;

namespace new_app.Controllers;

public class CustomersController : Controller
{
    private readonly ApplicationDbContext _context;

    public CustomersController(ApplicationDbContext context)
    {
        _context = context;
    }

    [Authorize(Roles = RoleName.Admin)]
    public IActionResult Index()
    {
        return View();
    }

    [Authorize(Roles = RoleName.Admin)]
    public IActionResult Form(int id = 0)
    {
        if (id == 0)
        {
            // New customer form
            return View(new Customer());
        }
        else
        {
            // Edit customer form
            var customer = _context.Customers.Find(id);
            
            if (customer == null)
                return NotFound();
                
            return View(customer);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Save(Customer customer)
    {
        if (!ModelState.IsValid)
        {
            return View("Form", customer);
        }

        if (customer.Id == 0)
        {
            // New customer
            await _context.Customers.AddAsync(customer);
        }
        else
        {
            // Update existing customer
            var customerInDb = await _context.Customers.FindAsync(customer.Id);
            
            if (customerInDb == null)
                return NotFound();
                
            customerInDb.Name = customer.Name;
            customerInDb.Birthdate = customer.Birthdate;
        }
        
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var customer = await _context.Customers.FindAsync(id);
        
        if (customer == null)
            return NotFound();
            
        _context.Customers.Remove(customer);
        await _context.SaveChangesAsync();
        
        return RedirectToAction(nameof(Index));
    }
}