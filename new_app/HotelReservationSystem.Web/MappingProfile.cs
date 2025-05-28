using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Web
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO mappings
            CreateMap<Country, CountryDto>();
            CreateMap<Hotel, HotelDto>();
            CreateMap<Customer, CustomerDto>();
            CreateMap<Order, OrderDto>();

            // DTO to Domain mappings
            CreateMap<CountryDto, Country>();
            CreateMap<HotelDto, Hotel>();
            CreateMap<CustomerDto, Customer>();
            CreateMap<OrderDto, Order>();
        }
    }
}