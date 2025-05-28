using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
    public class OrderService : IOrderService
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;
        private readonly ICustomerService _customerService;
        private readonly IHotelService _hotelService;

        public OrderService(
            ApplicationDbContext context, 
            IMapper mapper, 
            ICustomerService customerService, 
            IHotelService hotelService)
        {
            _context = context;
            _mapper = mapper;
            _customerService = customerService;
            _hotelService = hotelService;
        }

        public async Task<IEnumerable<OrderDto>> GetAllOrdersAsync()
        {
            var orders = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ThenInclude(h => h!.Country)
                .ToListAsync();
                
            return _mapper.Map<IEnumerable<OrderDto>>(orders);
        }

        public async Task<OrderDto?> GetOrderByIdAsync(int id)
        {
            var order = await _context.Orders
                .Include(o => o.Customer)
                .Include(o => o.Hotel)
                .ThenInclude(h => h!.Country)
                .SingleOrDefaultAsync(o => o.Id == id);
                
            return order != null ? _mapper.Map<OrderDto>(order) : null;
        }

        public async Task CreateOrderAsync(OrderDto orderDto)
        {
            var order = _mapper.Map<Order>(orderDto);
            
            // Set related entities
            order.Customer = await _customerService.GetCustomerEntityByIdAsync(orderDto.CustomerId);
            order.Hotel = await _hotelService.GetHotelEntityByIdAsync(orderDto.HotelId);
            
            // Calculate number of days and full price
            order.NumberOfDays = (order.EndDate - order.StartDate).Days;
            order.FullPrice = order.NumberOfDays * (order.Hotel?.PricePerNight ?? 0);
            
            _context.Orders.Add(order);
            await _context.SaveChangesAsync();
            orderDto.Id = order.Id;
        }

        public async Task DeleteOrderAsync(int id)
        {
            var order = await _context.Orders.FindAsync(id);
            if (order == null)
                throw new KeyNotFoundException($"Order with ID {id} not found.");
                
            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();
        }
    }
}