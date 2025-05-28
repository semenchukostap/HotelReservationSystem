using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers
{
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

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Index()
        {
            // The view uses AJAX to load data from the API
            return View();
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            var customer = new Customer();
            return View("Form", customer);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Edit(int id)
        {
            var customer = await _context.Customers.SingleOrDefaultAsync(c => c.Id == id);

            if (customer == null)
                return NotFound();

            return View("Form", customer);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Save(Customer customer)
        {
            if (!ModelState.IsValid)
            {
                return View("Form", customer);
            }

            try
            {
                if (customer.Id == 0)
                {
                    _context.Customers.Add(customer);
                    _logger.LogInformation("Created new customer: {CustomerName}", customer.Name);
                }
                else
                {
                    var customerInDb = await _context.Customers.FindAsync(customer.Id);
                    
                    if (customerInDb == null)
                        return NotFound();
                        
                    customerInDb.Name = customer.Name;
                    customerInDb.Birthdate = customer.Birthdate;
                    
                    _logger.LogInformation("Updated customer: {CustomerId}", customer.Id);
                }

                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving customer {CustomerId}", customer.Id);
                ModelState.AddModelError("", "An error occurred while saving. Please try again.");
                return View("Form", customer);
            }
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Details(int id)
        {
            var customer = await _context.Customers.FindAsync(id);

            if (customer == null)
                return NotFound();

            return View(customer);
        }
    }
}