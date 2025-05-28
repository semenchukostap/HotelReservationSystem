using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Create maps for entities to DTOs and vice versa
        CreateMap<Hotel, HotelDto>()
            .ForMember(dest => dest.Country, opt => opt.ExplicitExpansion());
        CreateMap<HotelDto, Hotel>()
            .ForMember(dest => dest.Country, opt => opt.Ignore())
            .ForMember(dest => dest.Orders, opt => opt.Ignore());
        
        CreateMap<Country, CountryDto>()
            .ForMember(dest => dest.Hotels, opt => opt.ExplicitExpansion());
        CreateMap<CountryDto, Country>()
            .ForMember(dest => dest.Hotels, opt => opt.Ignore());
        
        CreateMap<Order, NewOrderDto>();
        CreateMap<NewOrderDto, Order>()
            .ForMember(dest => dest.DateOrdered, opt => opt.MapFrom(_ => DateTime.UtcNow))
            .ForMember(dest => dest.FullPrice, opt => opt.Ignore())
            .ForMember(dest => dest.Customer, opt => opt.Ignore())
            .ForMember(dest => dest.Hotel, opt => opt.Ignore());

        CreateMap<Order, OrderDto>()
            .ForMember(dest => dest.CustomerName, opt => opt.MapFrom(src => src.Customer.FullName))
            .ForMember(dest => dest.HotelName, opt => opt.MapFrom(src => src.Hotel.Name));
        CreateMap<OrderDto, Order>()
            .ForMember(dest => dest.Customer, opt => opt.Ignore())
            .ForMember(dest => dest.Hotel, opt => opt.Ignore());
        
        // Mappings for Customer
        CreateMap<Customer, CustomerDto>()
            .ForMember(dest => dest.Orders, opt => opt.ExplicitExpansion());
        CreateMap<CustomerDto, Customer>()
            .ForMember(dest => dest.Orders, opt => opt.Ignore());
    }
}