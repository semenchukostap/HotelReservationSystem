using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Web.Controllers.API
{
    [Route("api/neworders")]
    [ApiController]
    public class OrdersApiController : ControllerBase
    {
        private readonly IOrderService _orderService;

        public OrdersApiController(IOrderService orderService)
        {
            _orderService = orderService;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> GetOrders()
        {
            var orders = await _orderService.GetAllOrdersAsync();
            return Ok(orders);
        }

        [HttpGet("{id}")]
        [AllowAnonymous]
        public async Task<IActionResult> GetOrder(int id)
        {
            var order = await _orderService.GetOrderByIdAsync(id);
            if (order == null)
                return NotFound();

            return Ok(order);
        }

        [HttpPost]
        public async Task<IActionResult> CreateOrder(OrderDto orderDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            await _orderService.CreateOrderAsync(orderDto);
            return CreatedAtAction(nameof(GetOrder), new { id = orderDto.Id }, orderDto);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            try
            {
                await _orderService.DeleteOrderAsync(id);
                return NoContent();
            }
            catch (KeyNotFoundException)
            {
                return NotFound();
            }
        }
    }
}