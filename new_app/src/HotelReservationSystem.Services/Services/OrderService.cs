using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Core.Services;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Services.Services;

public class OrderService : IOrderService
{
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;

    public OrderService(ApplicationDbContext context, IMapper mapper)
    {
        _context = context;
        _mapper = mapper;
    }

    public async Task<IEnumerable<OrderDto>> GetAllOrdersAsync()
    {
        var orders = await _context.Orders
            .Include(o => o.Hotel)
            .Include(o => o.Customer)
            .ToListAsync();
            
        return _mapper.Map<IEnumerable<OrderDto>>(orders);
    }

    public async Task<OrderDto?> GetOrderByIdAsync(int id)
    {
        var order = await _context.Orders
            .Include(o => o.Hotel)
            .Include(o => o.Customer)
            .FirstOrDefaultAsync(o => o.Id == id);
            
        return order != null ? _mapper.Map<OrderDto>(order) : null;
    }

    public async Task<int> CreateOrderAsync(NewOrderDto orderDto)
    {
        var order = _mapper.Map<Order>(orderDto);
        
        // Calculate number of days
        order.NumberOfDays = (orderDto.EndDate - orderDto.StartDate).Days;
        
        // Set reservation date
        order.ReservationDate = DateTime.Now;
        
        // Get hotel price for calculating full price
        var hotel = await _context.Hotels.FindAsync(orderDto.HotelId);
        if (hotel == null)
            throw new KeyNotFoundException($"Hotel with ID {orderDto.HotelId} not found.");
            
        // Calculate full price
        order.FullPrice = (decimal)(hotel.PricePerNight * order.NumberOfDays);
        
        _context.Orders.Add(order);
        await _context.SaveChangesAsync();
        
        return order.Id;
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