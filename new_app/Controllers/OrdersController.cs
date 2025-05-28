using HotelReservationSystem.DTOs;
using HotelReservationSystem.Services;
using HotelReservationSystem.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.Controllers;

[Authorize]
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

    [Authorize(Policy = "ViewOrders")]
    public async Task<IActionResult> Index() => 
        View(await _orderService.GetAllOrdersAsync());

    [Authorize(Policy = "ViewOrderDetails")]
    public async Task<IActionResult> Details(int id)
    {
        var order = await _orderService.GetOrderByIdAsync(id);
        return order is null ? NotFound() : View(order);
    }

    [Authorize(Policy = "CreateOrders")]
    public async Task<IActionResult> New()
    {
        var customers = await _customerService.GetAllCustomersAsync();
        var hotels = await _hotelService.GetAllHotelsAsync();

        return View(new OrderViewModel
        {
            CustomersList = customers.Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name }),
            HotelsList = hotels.Select(h => new SelectListItem { Value = h.Id.ToString(), Text = $"{h.Name} ({h.City}, {h.Country?.Name})" })
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = "CreateOrders")]
    public async Task<IActionResult> Create(NewOrderDto orderDto)
    {
        if (!ModelState.IsValid)
        {
            return await PrepareViewModel();
        }

        try
        {
            var orderId = await _orderService.CreateOrderAsync(orderDto);
            return RedirectToAction(nameof(Details), new { id = orderId });
        }
        catch (Exception ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return await PrepareViewModel();
        }

        async Task<IActionResult> PrepareViewModel()
        {
            var customers = await _customerService.GetAllCustomersAsync();
            var hotels = await _hotelService.GetAllHotelsAsync();

            return View("New", new OrderViewModel
            {
                CustomersList = customers.Select(c => new SelectListItem { Value = c.Id.ToString(), Text = c.Name }),
                HotelsList = hotels.Select(h => new SelectListItem { Value = h.Id.ToString(), Text = $"{h.Name} ({h.City}, {h.Country?.Name})" }),
                StartDate = orderDto.StartDate,
                EndDate = orderDto.EndDate
            });
        }
    }
}