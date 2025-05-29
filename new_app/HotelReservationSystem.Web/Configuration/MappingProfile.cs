using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using System;

namespace HotelReservationSystem.Web.Configuration
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Hotel, HotelDto>();
            CreateMap<Country, CountryDto>();
            CreateMap<Customer, CustomerDto>();
            CreateMap<Order, OrderDto>();
            
            // DTO to Domain
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
            CreateMap<CustomerDto, Customer>();
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(o => o.NumberOfDays, opt => opt.MapFrom(src => 
                    (src.EndDate - src.StartDate).Days));
        }
    }
}