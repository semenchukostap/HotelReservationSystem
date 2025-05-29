using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class NewOrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        private readonly ILogger<NewOrdersController> _logger;

        public NewOrdersController(ApplicationDbContext context, IMapper mapper, ILogger<NewOrdersController> logger)
        {
            _context = context;
            _mapper = mapper;
            _logger = logger;
        }

        // POST: api/NewOrders
        [HttpPost]
        public async Task<ActionResult<Order>> CreateOrder(NewOrderDto orderDto)
        {
            var customer = await _context.Customers.SingleOrDefaultAsync(c => c.Id == orderDto.CustomerId);
            if (customer == null)
                return NotFound("Customer not found");

            var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == orderDto.HotelId);
            if (hotel == null)
                return NotFound("Hotel not found");

            var order = _mapper.Map<Order>(orderDto);
            order.Customer = customer;
            order.Hotel = hotel;
            
            // Calculate number of days and full price
            order.NumberOfDays = (orderDto.EndDate - orderDto.StartDate).Days;
            order.FullPrice = hotel.PricePerNight * order.NumberOfDays;

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetOrder", "Orders", new { id = order.Id }, order);
        }
    }
}