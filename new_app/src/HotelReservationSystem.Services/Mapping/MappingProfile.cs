using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using System;

namespace HotelReservationSystem.Services.Mapping;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Hotel mappings
        CreateMap<Hotel, HotelDto>()
            .ForMember(dest => dest.CountryName, opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : string.Empty));
        CreateMap<HotelDto, Hotel>();
        
        // Country mappings
        CreateMap<Country, CountryDto>();
        CreateMap<CountryDto, Country>();
        
        // Customer mappings
        CreateMap<Customer, CustomerDto>();
        CreateMap<CustomerDto, Customer>();
        
        // Order mappings
        CreateMap<Order, OrderDto>()
            .ForMember(dest => dest.HotelName, opt => opt.MapFrom(src => src.Hotel != null ? src.Hotel.Name : string.Empty))
            .ForMember(dest => dest.CustomerName, opt => opt.MapFrom(src => src.Customer != null ? src.Customer.Name : string.Empty));
        
        CreateMap<NewOrderDto, Order>()
            .ForMember(dest => dest.ReservationDate, opt => opt.MapFrom(src => DateTime.Now))
            .ForMember(dest => dest.NumberOfDays, opt => opt.MapFrom(src => (src.EndDate - src.StartDate).Days))
            .ForMember(dest => dest.FullPrice, opt => opt.Ignore());
    }
}