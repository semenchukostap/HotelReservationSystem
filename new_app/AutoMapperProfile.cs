using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem;

public class AutoMapperProfile : Profile
{
    public AutoMapperProfile()
    {
        CreateMap<Country, CountryDto>();

        CreateMap<Hotel, HotelDto>()
            .ForMember(dest => dest.CountryName, 
                opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : null));
    }
}