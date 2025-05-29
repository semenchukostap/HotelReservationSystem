using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers
{
    public class CustomersController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<CustomersController> _logger;

        public CustomersController(ApplicationDbContext context, ILogger<CustomersController> logger)
        {
            _context = context;
            _logger = logger;
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Retrieving all customers");
            var customers = await _context.Customers.ToListAsync();
            return View(customers);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            _logger.LogInformation("Creating new customer form");
            var customer = new Customer();
            return View("Form", customer);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Edit(int id)
        {
            _logger.LogInformation("Editing customer with ID: {CustomerId}", id);
            
            var customer = await _context.Customers.FindAsync(id);

            if (customer == null)
            {
                _logger.LogWarning("Customer with ID: {CustomerId} not found", id);
                return NotFound();
            }

            return View("Form", customer);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Details(int id)
        {
            _logger.LogInformation("Viewing customer details with ID: {CustomerId}", id);
            
            var customer = await _context.Customers.FindAsync(id);
            
            if (customer == null)
            {
                _logger.LogWarning("Customer with ID: {CustomerId} not found", id);
                return NotFound();
            }

            return View(customer);
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(Customer customer)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid customer model state");
                return View("Form", customer);
            }

            try
            {
                if (customer.Id == 0)
                {
                    _logger.LogInformation("Adding new customer: {CustomerName}", customer.Name);
                    _context.Customers.Add(customer);
                }
                else
                {
                    _logger.LogInformation("Updating customer with ID: {CustomerId}", customer.Id);
                    var customerInDb = await _context.Customers.FindAsync(customer.Id);
                    
                    if (customerInDb == null)
                    {
                        _logger.LogWarning("Customer with ID: {CustomerId} not found for update", customer.Id);
                        return NotFound();
                    }
                    
                    customerInDb.Name = customer.Name;
                    customerInDb.Birthdate = customer.Birthdate;
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Customer saved successfully");
                
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving customer");
                ModelState.AddModelError("", "An error occurred while saving the customer.");
                return View("Form", customer);
            }
        }
    }
}
