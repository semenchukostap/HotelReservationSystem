using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class NewOrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        public NewOrdersController(ApplicationDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
        {
            return await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ToListAsync();
        }

        [HttpGet("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<Order>> GetOrder(int id)
        {
            var order = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .FirstOrDefaultAsync(o => o.Id == id);

            if (order == null)
                return NotFound();

            return order;
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<Order>> CreateNewOrder(NewOrderDto newOrder)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var customer = await _context.Customers.FindAsync(newOrder.CustomerId);
            if (customer == null)
                return NotFound("Customer not found");

            var hotel = await _context.Hotels.FindAsync(newOrder.HotelId);
            if (hotel == null)
                return NotFound("Hotel not found");

            var numOfDays = (int)(newOrder.EndDate - newOrder.StartDate).TotalDays;
            
            if (numOfDays <= 0)
                return BadRequest("End date must be after start date");

            var fullPrice = Math.Round((hotel.PricePerNight * numOfDays), 2);

            var order = new Order
            {
                Customer = customer,
                Hotel = hotel,
                DateOrdered = DateTime.Now,
                StartDate = newOrder.StartDate,
                EndDate = newOrder.EndDate,
                NumberOfDays = numOfDays,
                FullPrice = fullPrice
            };

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, order);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> UpdateOrder(int id, Order order)
        {
            if (id != order.Id || !ModelState.IsValid)
                return BadRequest();

            var orderInDb = await _context.Orders.FindAsync(id);

            if (orderInDb == null)
                return NotFound();

            // Update the order properties
            orderInDb.Customer = order.Customer;
            orderInDb.Hotel = order.Hotel;
            orderInDb.DateOrdered = order.DateOrdered;
            orderInDb.StartDate = order.StartDate;
            orderInDb.EndDate = order.EndDate;
            orderInDb.FullPrice = order.FullPrice;
            orderInDb.NumberOfDays = order.NumberOfDays;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await OrderExists(id))
                    return NotFound();
                else
                    throw;
            }

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            var order = await _context.Orders.FindAsync(id);
            
            if (order == null)
                return NotFound();

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        private async Task<bool> OrderExists(int id)
        {
            return await _context.Orders.AnyAsync(o => o.Id == id);
        }
    }
}