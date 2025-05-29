using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.DTOs;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Interface for order service operations
    /// </summary>
    public interface IOrderService
    {
        /// <summary>
        /// Gets all orders with related data
        /// </summary>
        Task<IEnumerable<Order>> GetAllOrdersAsync();
        
        /// <summary>
        /// Gets order by ID with related data
        /// </summary>
        Task<Order> GetOrderByIdAsync(int id);
        
        /// <summary>
        /// Creates a new order
        /// </summary>
        Task<Order> CreateOrderAsync(NewOrderDto newOrderDto);
        
        /// <summary>
        /// Updates an existing order
        /// </summary>
        Task UpdateOrderAsync(int id, Order order);
        
        /// <summary>
        /// Deletes an order by ID
        /// </summary>
        Task DeleteOrderAsync(int id);
    }

    /// <summary>
    /// Implementation of order service operations
    /// </summary>
    public class OrderService : IOrderService
    {
        private readonly ApplicationDbContext _context;

        public OrderService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Order>> GetAllOrdersAsync()
        {
            return await _context.Orders
                .Include(c => c.Customer)
                .Include(c => c.Hotel)
                .ToListAsync();
        }

        public async Task<Order> GetOrderByIdAsync(int id)
        {
            return await _context.Orders
                .Include(c => c.Customer)
                .Include(c => c.Hotel)
                .SingleOrDefaultAsync(c => c.Id == id);
        }

        public async Task<Order> CreateOrderAsync(NewOrderDto newOrderDto)
        {
            var customer = await _context.Customers.SingleAsync(c => c.Id == newOrderDto.CustomerId);
            var hotel = await _context.Hotels.SingleAsync(c => c.Id == newOrderDto.HotelId);

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

            return order;
        }

        public async Task UpdateOrderAsync(int id, Order order)
        {
            var orderInDb = await _context.Orders.SingleOrDefaultAsync(c => c.Id == id);
            
            if (orderInDb == null)
                throw new KeyNotFoundException($"Order with ID {id} not found.");

            orderInDb.Customer = order.Customer;
            orderInDb.Hotel = order.Hotel;
            orderInDb.DateOrdered = order.DateOrdered;
            orderInDb.StartDate = order.StartDate;
            orderInDb.EndDate = order.EndDate;
            orderInDb.FullPrice = order.FullPrice;
            orderInDb.NumberOfDays = order.NumberOfDays;

            await _context.SaveChangesAsync();
        }

        public async Task DeleteOrderAsync(int id)
        {
            var order = await _context.Orders.SingleOrDefaultAsync(c => c.Id == id);
            
            if (order == null)
                throw new KeyNotFoundException($"Order with ID {id} not found.");

            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();
        }
    }
}