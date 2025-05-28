using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
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
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                    .ThenInclude(h => h.Country)
                .ToListAsync();
        }

        public async Task<Order?> GetOrderByIdAsync(int id)
        {
            return await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                    .ThenInclude(h => h.Country)
                .FirstOrDefaultAsync(o => o.Id == id);
        }

        public async Task<int> CreateOrderAsync(NewOrderDto orderDto)
        {
            var customer = await _context.Customers.FindAsync(orderDto.CustomerId);
            var hotel = await _context.Hotels.FindAsync(orderDto.HotelId);

            if (customer == null || hotel == null)
            {
                throw new ArgumentException("Customer or Hotel not found");
            }

            var numberOfDays = (orderDto.EndDate - orderDto.StartDate).Days;
            var fullPrice = numberOfDays * hotel.PricePerNight;

            var order = new Order
            {
                Customer = customer,
                Hotel = hotel,
                DateOrdered = DateTime.Now,
                StartDate = orderDto.StartDate,
                EndDate = orderDto.EndDate,
                NumberOfDays = numberOfDays,
                FullPrice = fullPrice
            };

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return order.Id;
        }

        public async Task DeleteOrderAsync(int id)
        {
            var order = await _context.Orders.FindAsync(id);
            if (order != null)
            {
                _context.Orders.Remove(order);
                await _context.SaveChangesAsync();
            }
        }
    }
}