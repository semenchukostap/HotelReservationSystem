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

        private readonly IConfiguration _configuration;

        public NewOrdersController(
            ApplicationDbContext context, 
            IMapper mapper, 
            ILogger<NewOrdersController> logger,
            IConfiguration configuration)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        [HttpGet]
        [Authorize(Roles = RoleName.CanManageHotels)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders([FromQuery] int? pageNumber, [FromQuery] int? pageSize)
        {
            try
            {
                _logger.LogInformation("Getting orders with pagination: Page {PageNumber}, Size {PageSize}", 
                    pageNumber, pageSize);

                var query = _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                    .AsQueryable();

                // Apply pagination if specified
                if (pageNumber.HasValue && pageSize.HasValue)
                {
                    int defaultPageSize = _configuration.GetValue<int>("Pagination:DefaultPageSize", 10);
                    int maxPageSize = _configuration.GetValue<int>("Pagination:MaxPageSize", 50);
                    
                    int size = Math.Min(pageSize.Value > 0 ? pageSize.Value : defaultPageSize, maxPageSize);
                    int skip = ((pageNumber.Value > 0 ? pageNumber.Value : 1) - 1) * size;
                    
                    query = query.Skip(skip).Take(size);
                }

                var orders = await query.ToListAsync();
                
                _logger.LogInformation("Retrieved {Count} orders", orders.Count);
                return Ok(orders);
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
        public async Task<IActionResult> UpdateOrder(int id, UpdateOrderDto orderDto)
        {
            try
            {
                _logger.LogInformation("Updating order with ID: {OrderId}", id);
                
                if (id != orderDto.Id || !ModelState.IsValid)
                {
                    _logger.LogWarning("Invalid model state or ID mismatch for order update");
                    return BadRequest(ModelState);
                }

                var orderInDb = await _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                    .FirstOrDefaultAsync(o => o.Id == id);

                if (orderInDb == null)
                {
                    _logger.LogWarning("Order with ID: {OrderId} not found for update", id);
                    return NotFound();
                }

                // Verify related entities exist
                var customer = await _context.Customers.FindAsync(orderDto.CustomerId);
                if (customer == null)
                {
                    _logger.LogWarning("Customer with ID: {CustomerId} not found during order update", orderDto.CustomerId);
                    return BadRequest("Customer not found");
                }

                var hotel = await _context.Hotels.FindAsync(orderDto.HotelId);
                if (hotel == null)
                {
                    _logger.LogWarning("Hotel with ID: {HotelId} not found during order update", orderDto.HotelId);
                    return BadRequest("Hotel not found");
                }

                // Calculate number of days and price
                var numOfDays = (int)(orderDto.EndDate - orderDto.StartDate).TotalDays;
                if (numOfDays <= 0)
                {
                    _logger.LogWarning("Invalid date range in order update: End date must be after start date");
                    return BadRequest("End date must be after start date");
                }
                
                var fullPrice = Math.Round((hotel.PricePerNight * numOfDays), 2);

                // Update the order properties
                orderInDb.Customer = customer;
                orderInDb.Hotel = hotel;
                orderInDb.StartDate = orderDto.StartDate;
                orderInDb.EndDate = orderDto.EndDate;
                orderInDb.NumberOfDays = numOfDays;
                orderInDb.FullPrice = fullPrice;

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

        [HttpGet("search")]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<IEnumerable<Order>>> SearchOrders([FromQuery] OrderSearchParams searchParams)
        {
            try
            {
                _logger.LogInformation("Searching for orders with parameters: {@SearchParams}", searchParams);
                
                IQueryable<Order> query = _context.Orders
                    .Include(o => o.Customer)
                    .Include(o => o.Hotel)
                    .AsQueryable();

                // Apply filters if they exist
                if (searchParams.CustomerId.HasValue)
                {
                    query = query.Where(o => o.Customer.Id == searchParams.CustomerId.Value);
                }

                if (searchParams.HotelId.HasValue)
                {
                    query = query.Where(o => o.Hotel.Id == searchParams.HotelId.Value);
                }

                if (searchParams.FromDate.HasValue)
                {
                    query = query.Where(o => o.StartDate >= searchParams.FromDate.Value);
                }

                if (searchParams.ToDate.HasValue)
                {
                    query = query.Where(o => o.EndDate <= searchParams.ToDate.Value);
                }

                if (searchParams.MinPrice.HasValue)
                {
                    query = query.Where(o => o.FullPrice >= searchParams.MinPrice.Value);
                }

                if (searchParams.MaxPrice.HasValue)
                {
                    query = query.Where(o => o.FullPrice <= searchParams.MaxPrice.Value);
                }

                // Apply sorting
                query = searchParams.SortBy?.ToLower() switch
                {
                    "date" => searchParams.SortDirection?.ToLower() == "desc" 
                        ? query.OrderByDescending(o => o.DateOrdered)
                        : query.OrderBy(o => o.DateOrdered),
                    "price" => searchParams.SortDirection?.ToLower() == "desc"
                        ? query.OrderByDescending(o => o.FullPrice)
                        : query.OrderBy(o => o.FullPrice),
                    "customer" => searchParams.SortDirection?.ToLower() == "desc"
                        ? query.OrderByDescending(o => o.Customer.Name)
                        : query.OrderBy(o => o.Customer.Name),
                    "hotel" => searchParams.SortDirection?.ToLower() == "desc"
                        ? query.OrderByDescending(o => o.Hotel.Name)
                        : query.OrderBy(o => o.Hotel.Name),
                    _ => query.OrderByDescending(o => o.DateOrdered) // Default sort
                };

                // Apply pagination if specified
                if (searchParams.PageNumber.HasValue && searchParams.PageSize.HasValue)
                {
                    int pageSize = Math.Min(searchParams.PageSize.Value, 50); // Limit max page size
                    int skip = (searchParams.PageNumber.Value - 1) * pageSize;
                    
                    query = query.Skip(skip).Take(pageSize);
                }

                var results = await query.ToListAsync();
                
                _logger.LogInformation("Order search returned {Count} results", results.Count);
                return Ok(results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while searching for orders");
                return StatusCode(500, "An error occurred while searching for orders");
            }
        }
    }
}
