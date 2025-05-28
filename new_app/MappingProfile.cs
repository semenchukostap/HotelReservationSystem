using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Create maps for entities to DTOs and vice versa
        CreateMap<Hotel, HotelDto>();
        CreateMap<HotelDto, Hotel>();
        
        CreateMap<Country, CountryDto>();
        CreateMap<CountryDto, Country>();
        
        CreateMap<Order, NewOrderDto>();
        CreateMap<NewOrderDto, Order>()
            .ForMember(dest => dest.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
            .ForMember(dest => dest.FullPrice, opt => opt.Ignore());
        
        // Add more mappings as needed for Customer and other entities
        CreateMap<Customer, CustomerDto>();
        CreateMap<CustomerDto, Customer>();
    }
}