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
using Microsoft.Extensions.Logging;

namespace HotelReservationSystem.Controllers.API
{
    [Route("api/[controller]")]
    [ApiController]
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

        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
        {
            try
            {
                _logger.LogInformation("Getting all orders");
                return await _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving orders");
                return StatusCode(500, "An error occurred while retrieving orders");
            }
        }

        [HttpGet("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<Order>> GetOrder(int id)
        {
            try
            {
                _logger.LogInformation("Getting order with ID: {OrderId}", id);
                var order = await _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                    .FirstOrDefaultAsync(o => o.Id == id);

                if (order == null)
                {
                    _logger.LogWarning("Order with ID: {OrderId} not found", id);
                    return NotFound();
                }

                return order;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving order with ID: {OrderId}", id);
                return StatusCode(500, "An error occurred while retrieving the order");
            }
        }

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<Order>> CreateNewOrder(NewOrderDto newOrder)
        {
            try
            {
                _logger.LogInformation("Creating new order for customer ID: {CustomerId}, hotel ID: {HotelId}", newOrder.CustomerId, newOrder.HotelId);
                
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("Invalid model state for new order");
                    return BadRequest(ModelState);
                }

                var customer = await _context.Customers.FindAsync(newOrder.CustomerId);
                if (customer == null)
                {
                    _logger.LogWarning("Customer with ID: {CustomerId} not found", newOrder.CustomerId);
                    return NotFound("Customer not found");
                }

                var hotel = await _context.Hotels.FindAsync(newOrder.HotelId);
                if (hotel == null)
                {
                    _logger.LogWarning("Hotel with ID: {HotelId} not found", newOrder.HotelId);
                    return NotFound("Hotel not found");
                }

                var numOfDays = (int)(newOrder.EndDate - newOrder.StartDate).TotalDays;
                
                if (numOfDays <= 0)
                {
                    _logger.LogWarning("Invalid date range: End date must be after start date");
                    return BadRequest("End date must be after start date");
                }

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

                _logger.LogInformation("Order created successfully with ID: {OrderId}", order.Id);
                return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, order);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while creating a new order");
                return StatusCode(500, "An error occurred while creating the order");
            }
        }

        [HttpPut("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> UpdateOrder(int id, Order order)
        {
            try
            {
                _logger.LogInformation("Updating order with ID: {OrderId}", id);
                
                if (id != order.Id || !ModelState.IsValid)
                {
                    _logger.LogWarning("Invalid model state or ID mismatch for order update");
                    return BadRequest();
                }

                var orderInDb = await _context.Orders.FindAsync(id);

                if (orderInDb == null)
                {
                    _logger.LogWarning("Order with ID: {OrderId} not found for update", id);
                    return NotFound();
                }

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
                catch (DbUpdateConcurrencyException ex)
                {
                    if (!await OrderExists(id))
                    {
                        _logger.LogWarning("Order with ID: {OrderId} no longer exists during update", id);
                        return NotFound();
                    }
                    else
                    {
                        _logger.LogError(ex, "Concurrency exception when updating order with ID: {OrderId}", id);
                        throw;
                    }
                }

                _logger.LogInformation("Order with ID: {OrderId} updated successfully", id);
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while updating order with ID: {OrderId}", id);
                return StatusCode(500, "An error occurred while updating the order");
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            try
            {
                _logger.LogInformation("Deleting order with ID: {OrderId}", id);
                
                var order = await _context.Orders.FindAsync(id);
                
                if (order == null)
                {
                    _logger.LogWarning("Order with ID: {OrderId} not found for deletion", id);
                    return NotFound();
                }

                _context.Orders.Remove(order);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Order with ID: {OrderId} deleted successfully", id);
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while deleting order with ID: {OrderId}", id);
                return StatusCode(500, "An error occurred while deleting the order");
            }
        }

        private async Task<bool> OrderExists(int id)
        {
            return await _context.Orders.AnyAsync(o => o.Id == id);
        }
    }
}