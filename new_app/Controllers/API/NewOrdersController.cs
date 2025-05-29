using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Controllers.API;

[Route("api/[controller]")]
[ApiController]
public class NewOrdersController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public NewOrdersController(ApplicationDbContext context)
    {
        _context = context;
    }

    // POST: api/neworders
    [HttpPost]
    public async Task<IActionResult> CreateOrder([FromBody] NewOrderDto orderDto)
    {
        // Validate model
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        // Get customer and hotel
        var customer = await _context.Customers.FindAsync(orderDto.CustomerId);
        var hotel = await _context.Hotels.FindAsync(orderDto.HotelId);

        if (customer == null)
            return BadRequest("Invalid customer ID");

        if (hotel == null)
            return BadRequest("Invalid hotel ID");

        // Calculate number of days
        var numberOfDays = (orderDto.EndDate - orderDto.StartDate).Days;
        
        if (numberOfDays <= 0)
            return BadRequest("End date must be after start date");

        // Create new order
        var order = new Order
        {
            Customer = customer,
            Hotel = hotel,
            DateOrdered = DateTime.Now,
            StartDate = orderDto.StartDate,
            EndDate = orderDto.EndDate,
            NumberOfDays = numberOfDays,
            FullPrice = numberOfDays * hotel.PricePerNight
        };

        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        return Ok(order);
    }
}