using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Controllers.API
{
    [ApiController]
    [Route("api/[controller]")]
    public class OrdersController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public OrdersController(ApplicationDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Gets all orders with related customer and hotel data
        /// </summary>
        /// <returns>List of all orders</returns>
        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(typeof(IEnumerable<Order>), 200)]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
        {
            return await _context.Orders
                .Include(c => c.Customer)
                .Include(c => c.Hotel)
                .ToListAsync();
        }

        /// <summary>
        /// Gets a specific order by ID
        /// </summary>
        /// <param name="id">Order ID</param>
        /// <returns>Order details</returns>
        [HttpGet("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(typeof(Order), 200)]
        [ProducesResponseType(404)]
        public async Task<ActionResult<Order>> GetOrder(int id)
        {
            var order = await _context.Orders
                .Include(c => c.Customer)
                .Include(c => c.Hotel)
                .FirstOrDefaultAsync(c => c.Id == id);

            if (order == null)
            {
                return NotFound();
            }

            return order;
        }

        /// <summary>
        /// Creates a new order
        /// </summary>
        /// <param name="orderDto">Order details</param>
        /// <returns>Status of creation</returns>
        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> CreateOrder(NewOrderDto orderDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var customer = await _context.Customers.FirstOrDefaultAsync(c => c.Id == orderDto.CustomerId);
            if (customer == null)
            {
                return NotFound("Customer not found");
            }

            var hotel = await _context.Hotels.FirstOrDefaultAsync(c => c.Id == orderDto.HotelId);
            if (hotel == null)
            {
                return NotFound("Hotel not found");
            }

            var numOfDays = Convert.ToInt32((orderDto.EndDate - orderDto.StartDate).TotalDays);
            var fullPrice = Math.Round((hotel.PricePerNight * numOfDays), 2);

            var order = new Order
            {
                Customer = customer,
                Hotel = hotel,
                DateOrdered = DateTime.Now,
                StartDate = orderDto.StartDate,
                EndDate = orderDto.EndDate,
                NumberOfDays = numOfDays,
                FullPrice = fullPrice
            };

            await _context.Orders.AddAsync(order);
            await _context.SaveChangesAsync();

            return Ok();
        }

        /// <summary>
        /// Updates an existing order
        /// </summary>
        /// <param name="id">Order ID</param>
        /// <param name="orderDto">Updated order details</param>
        /// <returns>Status of update</returns>
        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> UpdateOrder(int id, [FromBody] Order order)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != order.Id)
            {
                return BadRequest("ID mismatch");
            }

            var orderInDb = await _context.Orders.FirstOrDefaultAsync(c => c.Id == id);
            if (orderInDb == null)
            {
                return NotFound();
            }

            // Get related objects
            var customer = await _context.Customers.FirstOrDefaultAsync(c => c.Id == orderInDb.Customer.Id);
            var hotel = await _context.Hotels.FirstOrDefaultAsync(h => h.Id == orderInDb.Hotel.Id);

            if (customer == null || hotel == null)
            {
                return NotFound("Related customer or hotel not found");
            }

            // Update order properties
            orderInDb.Customer = customer;
            orderInDb.Hotel = hotel;
            orderInDb.DateOrdered = order.DateOrdered;
            orderInDb.StartDate = order.StartDate;
            orderInDb.EndDate = order.EndDate;
            orderInDb.NumberOfDays = order.NumberOfDays;
            orderInDb.FullPrice = order.FullPrice;

            try
            {
                await _context.SaveChangesAsync();
                return Ok();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!OrderExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// Deletes an order
        /// </summary>
        /// <param name="id">Order ID</param>
        /// <returns>Status of deletion</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            var order = await _context.Orders.FirstOrDefaultAsync(c => c.Id == id);
            
            if (order == null)
            {
                return NotFound();
            }

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();

            return Ok();
        }

        private bool OrderExists(int id)
        {
            return _context.Orders.Any(e => e.Id == id);
        }
    }
}