using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers
{
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IOrderService _orderService;

        public OrdersController(ApplicationDbContext context, IOrderService orderService)
        {
            _context = context;
            _orderService = orderService;
        }

        [Authorize(Policy = RoleName.CanManageHotels)]
        public IActionResult Index()
        {
            return View();
        }

        [Authorize(Policy = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            return View();
        }

        [Authorize(Policy = RoleName.CanManageHotels)]
        public async Task<IActionResult> Details(int id)
        {
            var order = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .FirstOrDefaultAsync(o => o.Id == id);

            if (order == null)
            {
                return NotFound();
            }

            return View(order);
        }
    }
}