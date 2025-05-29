using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Web.Controllers.Api
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

        [HttpPost]
        [Authorize(Roles = RoleName.CanManageHotels)]
        public async Task<ActionResult<int>> CreateNewOrder(NewOrderDto newOrderDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var customer = await _context.Customers.SingleOrDefaultAsync(c => c.Id == newOrderDto.CustomerId);
            if (customer == null)
                return BadRequest("Customer not found");

            var hotel = await _context.Hotels.SingleOrDefaultAsync(h => h.Id == newOrderDto.HotelId);
            if (hotel == null)
                return BadRequest("Hotel not found");

            var order = _mapper.Map<Order>(newOrderDto);
            order.Customer = customer;
            order.Hotel = hotel;
            order.DateOrdered = DateTime.Now;
            order.NumberOfDays = (newOrderDto.EndDate - newOrderDto.StartDate).Days;
            order.FullPrice = order.NumberOfDays * hotel.PricePerNight;

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            return Ok(order.Id);
        }
    }
}