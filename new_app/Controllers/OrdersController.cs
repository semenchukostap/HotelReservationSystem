using HotelReservationSystem.DTOs;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.Controllers
{
    public class OrdersController : Controller
    {
        private readonly IOrderService _orderService;
        private readonly ICustomerService _customerService;
        private readonly IHotelService _hotelService;

        public OrdersController(IOrderService orderService, ICustomerService customerService, IHotelService hotelService)
        {
            _orderService = orderService;
            _customerService = customerService;
            _hotelService = hotelService;
        }

        public async Task<IActionResult> Index()
        {
            var orders = await _orderService.GetAllOrdersAsync();
            return View(orders);
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

            var viewModel = new OrderViewModel
            {
                CustomersList = customers.Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name }),
                HotelsList = hotels.Select(h => new SelectListItem { Value = h.Id.ToString(), Text = $"{h.Name} ({h.City}, {h.Country?.Name})" })
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(NewOrderDto orderDto)
        {
            if (!ModelState.IsValid)
            {
                var customers = await _customerService.GetAllCustomersAsync();
                var hotels = await _hotelService.GetAllHotelsAsync();

                var viewModel = new OrderViewModel
                {
                    CustomersList = customers.Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name }),
                    HotelsList = hotels.Select(h => new SelectListItem { Value = h.Id.ToString(), Text = $"{h.Name} ({h.City}, {h.Country?.Name})" }),
                    StartDate = orderDto.StartDate,
                    EndDate = orderDto.EndDate
                };

                return View("New", viewModel);
            }

            try
            {
                var orderId = await _orderService.CreateOrderAsync(orderDto);
                return RedirectToAction("Details", new { id = orderId });
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
                
                var customers = await _customerService.GetAllCustomersAsync();
                var hotels = await _hotelService.GetAllHotelsAsync();

                var viewModel = new OrderViewModel
                {
                    CustomersList = customers.Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name }),
                    HotelsList = hotels.Select(h => new SelectListItem { Value = h.Id.ToString(), Text = $"{h.Name} ({h.City}, {h.Country?.Name})" }),
                    StartDate = orderDto.StartDate,
                    EndDate = orderDto.EndDate
                };

                return View("New", viewModel);
            }
        }
    }
}