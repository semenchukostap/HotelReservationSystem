using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OrdersController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<OrdersController> _logger;

        // Dependency injection via constructor
        public OrdersController(ApplicationDbContext context, ILogger<OrdersController> logger)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        // GET: Orders
        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Index()
        {
            _logger.LogInformation("Loading Orders Index view at {Time}", DateTimeOffset.UtcNow);
            // In legacy app, Index() doesn't load orders - they're loaded via AJAX
            // Just return the empty view which will use DataTables with AJAX
            return View();
        }

        // GET: Orders/Details/5
        [HttpGet("Details/{id:int}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> Details(int id)
        {
            _logger.LogInformation("Loading order details for ID: {OrderId} at {Time}", id, DateTimeOffset.UtcNow);
            
            try
            {
                // In the new version, we'll load and pass the order to the view
                var order = await _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                        .ThenInclude(h => h.Country)
                    .AsNoTracking()
                    .FirstOrDefaultAsync(o => o.Id == id);

                if (order == null)
                {
                    _logger.LogWarning("Order with ID {OrderId} not found", id);
                    return NotFound();
                }

                return View(order);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving order details for ID: {OrderId}", id);
                return StatusCode(500, "An error occurred while retrieving order details.");
            }
        }

        // GET: Orders/New
        [HttpGet("New")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> New()
        {
            _logger.LogInformation("Loading New Order form at {Time}", DateTimeOffset.UtcNow);
            
            try
            {
                // Load the customers and hotels for the dropdown functionality
                var customers = await _context.Customers
                    .AsNoTracking()
                    .ToListAsync();
                
                var hotels = await _context.Hotels
                    .AsNoTracking()
                    .ToListAsync();

                var viewModel = new NewOrderViewModel
                {
                    Customers = customers,
                    Hotels = hotels
                };

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading data for new order form");
                return StatusCode(500, "An error occurred while loading the new order form.");
            }
        }
    }
}