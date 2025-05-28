using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Hotel mappings
        CreateMap<Hotel, HotelDto>();
        CreateMap<HotelDto, Hotel>();

        // Country mappings
        CreateMap<Country, CountryDto>();

        // Order mappings
        CreateMap<NewOrderDto, Order>();
    }
}