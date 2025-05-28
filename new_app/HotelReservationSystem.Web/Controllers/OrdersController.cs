using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.Web.Controllers
{
    public class OrdersController : Controller
    {
        private readonly IOrderService _orderService;
        private readonly ICustomerService _customerService;
        private readonly IHotelService _hotelService;

        public OrdersController(
            IOrderService orderService,
            ICustomerService customerService,
            IHotelService hotelService)
        {
            _orderService = orderService;
            _customerService = customerService;
            _hotelService = hotelService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Details(int id)
        {
            var order = await _orderService.GetOrderByIdAsync(id);
            if (order == null)
                return NotFound();

            return View(order);
        }

        public async Task<IActionResult> New()
        {
            var customers = await _customerService.GetAllCustomersAsync();
            var hotels = await _hotelService.GetAllHotelsAsync();

            ViewBag.Customers = customers.Select(c => new SelectListItem
            {
                Value = c.Id.ToString(),
                Text = c.Name
            });

            ViewBag.Hotels = hotels.Select(h => new SelectListItem
            {
                Value = h.Id.ToString(),
                Text = $"{h.Name} - {h.City} ({h.Stars} stars)"
            });

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Save(OrderDto orderDto)
        {
            if (!ModelState.IsValid)
            {
                var customers = await _customerService.GetAllCustomersAsync();
                var hotels = await _hotelService.GetAllHotelsAsync();

                ViewBag.Customers = customers.Select(c => new SelectListItem
                {
                    Value = c.Id.ToString(),
                    Text = c.Name
                });

                ViewBag.Hotels = hotels.Select(h => new SelectListItem
                {
                    Value = h.Id.ToString(),
                    Text = $"{h.Name} - {h.City} ({h.Stars} stars)"
                });

                return View("New", orderDto);
            }

            // Set date ordered to current date
            orderDto.DateOrdered = DateTime.Now;

            await _orderService.CreateOrderAsync(orderDto);

            return RedirectToAction("Index");
        }
    }
}