using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Controllers.API;

[Route("api/[controller]")]
[ApiController]
public class OrdersController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public OrdersController(ApplicationDbContext context)
    {
        _context = context;
    }

    // GET: api/Orders
    [HttpGet]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
    {
        return await _context.Orders
            .Include(o => o.Customer)
            .Include(o => o.Hotel)
                .ThenInclude(h => h.Country)
            .ToListAsync();
    }

    // GET: api/Orders/5
    [HttpGet("{id}")]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<ActionResult<Order>> GetOrder(int id)
    {
        var order = await _context.Orders
            .Include(o => o.Customer)
            .Include(o => o.Hotel)
            .FirstOrDefaultAsync(o => o.Id == id);

        if (order == null)
        {
            return NotFound();
        }

        return order;
    }

    // POST: api/Orders
    [HttpPost]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> CreateOrder(NewOrderDto newOrderDto)
    {
        var customer = await _context.Customers.FindAsync(newOrderDto.CustomerId);
        if (customer == null)
            return BadRequest("Invalid Customer ID");

        var hotel = await _context.Hotels.FindAsync(newOrderDto.HotelId);
        if (hotel == null)
            return BadRequest("Invalid Hotel ID");

        var numOfDays = (int)(newOrderDto.EndDate - newOrderDto.StartDate).TotalDays;
        if (numOfDays <= 0)
            return BadRequest("End date must be after start date");

        var fullPrice = Math.Round((hotel.PricePerNight * numOfDays), 2);

        var order = new Order
        {
            Customer = customer,
            Hotel = hotel,
            DateOrdered = DateTime.Now,
            StartDate = newOrderDto.StartDate,
            EndDate = newOrderDto.EndDate,
            NumberOfDays = numOfDays,
            FullPrice = fullPrice
        };

        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, order);
    }

    // DELETE: api/Orders/5
    [HttpDelete("{id}")]
    [Authorize(Roles = RoleName.Admin)]
    public async Task<IActionResult> DeleteOrder(int id)
    {
        var order = await _context.Orders.FindAsync(id);
        if (order == null)
        {
            return NotFound();
        }

        _context.Orders.Remove(order);
        await _context.SaveChangesAsync();

        return NoContent();
    }
}