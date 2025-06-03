using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Controllers.Api
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "CanManageHotels")]
    public class NewOrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public NewOrdersController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpPost]
        public async Task<ActionResult<Order>> CreateOrder(NewOrderDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var customer = await _context.Customers.FindAsync(dto.CustomerId);
            if (customer == null)
                return BadRequest("Invalid Customer ID");

            var hotel = await _context.Hotels.FindAsync(dto.HotelId);
            if (hotel == null)
                return BadRequest("Invalid Hotel ID");

            // Calculate number of days and validate dates
            var numberOfDays = (dto.EndDate - dto.StartDate).Days;
            if (numberOfDays <= 0)
                return BadRequest("End date must be after start date");

            // Calculate full price
            var fullPrice = numberOfDays * hotel.PricePerNight;

            var order = new Order
            {
                Customer = customer,
                CustomerId = customer.Id,
                Hotel = hotel,
                HotelId = hotel.Id,
                DateOrdered = DateTime.Now,
                StartDate = dto.StartDate,
                EndDate = dto.EndDate,
                NumberOfDays = numberOfDays,
                FullPrice = fullPrice
            };

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetOrder", "Orders", new { id = order.Id }, order);
        }
    }
}