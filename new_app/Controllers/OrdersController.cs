using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Controllers
{
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _context;

        // Dependency injection via constructor
        public OrdersController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: Orders
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Index()
        {
            // In legacy app, Index() doesn't load orders - they're loaded via AJAX
            // Just return the empty view which will use DataTables with AJAX
            return View();
        }

        // GET: Orders/Details/5
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Details(int id)
        {
            // In the new version, we'll load and pass the order to the view
            var order = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ThenInclude(h => h.Country)
                .FirstOrDefaultAsync(o => o.Id == id);

            if (order == null)
                return NotFound();

            return View(order);
        }

        // GET: Orders/New
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            // In the new version, we'll load the customers and hotels for the typeahead
            var customers = await _context.Customers.ToListAsync();
            var hotels = await _context.Hotels.ToListAsync();

            var viewModel = new NewOrderViewModel
            {
                Customers = customers,
                Hotels = hotels
            };

            return View(viewModel);
        }
    }
}