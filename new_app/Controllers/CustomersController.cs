using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;
using HotelReservationSystem.Data;

namespace HotelReservationSystem.Controllers
{
    public class CustomersController : Controller
    {
        private readonly ApplicationDbContext _context;

        public CustomersController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Index()
        {
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
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(Customer customer)
        {
            if (!ModelState.IsValid)
            {
                return View("Form", customer);
            }

            if (customer.Id == 0)
                await _context.Customers.AddAsync(customer);
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
}