using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Configuration;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<Hotel, HotelDto>();
        CreateMap<HotelDto, Hotel>();
        
        CreateMap<Country, CountryDto>();
    }
}