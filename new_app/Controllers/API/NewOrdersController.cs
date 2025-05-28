using HotelReservationSystem.DTOs;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class NewOrdersController : ControllerBase
    {
        private readonly IOrderService _orderService;

        public NewOrdersController(IOrderService orderService)
        {
            _orderService = orderService;
        }

        [HttpPost]
        public async Task<IActionResult> CreateOrder(NewOrderDto orderDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            try
            {
                var orderId = await _orderService.CreateOrderAsync(orderDto);
                return Ok(new { Id = orderId });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}