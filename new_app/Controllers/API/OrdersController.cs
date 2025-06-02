using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public OrdersController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
        {
            return await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ToListAsync();
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        [HttpGet("{id}")]
        public async Task<ActionResult<Order>> GetOrder(int id)
        {
            var order = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .SingleOrDefaultAsync(o => o.Id == id);

            if (order == null)
                return NotFound();

            return order;
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> CreateNewOrder(NewOrderDto newOrderDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var customer = await _context.Customers.SingleAsync(c => c.Id == newOrderDto.CustomerId);
            var hotel = await _context.Hotels.SingleAsync(h => h.Id == newOrderDto.HotelId);

            var numOfDays = Convert.ToInt32((newOrderDto.EndDate - newOrderDto.StartDate).TotalDays);
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

            await _context.Orders.AddAsync(order);
            await _context.SaveChangesAsync();

            return Ok();
        }

        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> UpdateOrder(int id, Order order)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            if (id != order.Id)
                return BadRequest();

            var orderInDb = await _context.Orders.SingleOrDefaultAsync(o => o.Id == id);

            if (orderInDb == null)
                return NotFound();

            orderInDb.Customer = order.Customer;
            orderInDb.Hotel = order.Hotel;
            orderInDb.DateOrdered = order.DateOrdered;
            orderInDb.StartDate = order.StartDate;
            orderInDb.EndDate = order.EndDate;
            orderInDb.FullPrice = order.FullPrice;
            orderInDb.NumberOfDays = order.NumberOfDays;

            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<Order>> DeleteOrder(int id)
        {
            var order = await _context.Orders.SingleOrDefaultAsync(o => o.Id == id);

            if (order == null)
                return NotFound();

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();

            return order;
        }
    }
}