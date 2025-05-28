using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Entity to DTO mappings
        CreateMap<Hotel, HotelDto>();
        CreateMap<Country, CountryDto>();
        CreateMap<Customer, CustomerDto>();
        CreateMap<Order, OrderDto>();
        CreateMap<Order, NewOrderDto>();

        // DTO to Entity mappings
        CreateMap<HotelDto, Hotel>()
            .ForMember(h => h.Country, opt => opt.Ignore()); // Ignore navigation property

        CreateMap<CountryDto, Country>();
        
        CreateMap<NewOrderDto, Order>()
            .ForMember(o => o.Id, opt => opt.Ignore())
            .ForMember(o => o.Customer, opt => opt.Ignore())
            .ForMember(o => o.Hotel, opt => opt.Ignore())
            .ForMember(o => o.DateOrdered, opt => opt.MapFrom(_ => DateTime.Now))
            .ForMember(o => o.FullPrice, opt => opt.Ignore());
    }
}
