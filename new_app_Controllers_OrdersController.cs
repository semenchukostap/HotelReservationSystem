using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;
using System.Threading.Tasks;

namespace new_app.Controllers
{
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _context;

        public OrdersController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Index()
        {
            var orders = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ThenInclude(h => h.Country)
                .ToListAsync();

            return View(orders);
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            return View();
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
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
}