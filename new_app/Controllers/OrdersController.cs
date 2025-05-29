using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;

namespace new_app.Controllers
{
    [Authorize(Roles = RoleName.Admin)]
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<OrdersController> _logger;

        public OrdersController(ApplicationDbContext context, ILogger<OrdersController> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IActionResult> Index()
        {
            var orders = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ToListAsync();

            return View(orders);
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

        public async Task<IActionResult> New()
        {
            var customers = await _context.Customers.ToListAsync();
            var hotels = await _context.Hotels.ToListAsync();

            ViewBag.Customers = customers;
            ViewBag.Hotels = hotels;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(Order order)
        {
            if (!ModelState.IsValid)
            {
                var customers = await _context.Customers.ToListAsync();
                var hotels = await _context.Hotels.ToListAsync();

                ViewBag.Customers = customers;
                ViewBag.Hotels = hotels;

                return View("New", order);
            }

            // Calculate number of days and full price
            var hotel = await _context.Hotels.SingleAsync(h => h.Id == order.Hotel!.Id);
            order.NumberOfDays = (order.EndDate - order.StartDate).Days;
            order.FullPrice = hotel.PricePerNight * order.NumberOfDays;
            order.DateOrdered = DateTime.Now;

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index");
        }
    }
}