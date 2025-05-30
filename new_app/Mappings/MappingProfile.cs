using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Hotel => HotelDto
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.Country, opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : string.Empty));
            
            // HotelDto => Hotel
            CreateMap<HotelDto, Hotel>();
            
            // Country => CountryDto
            CreateMap<Country, CountryDto>();
            
            // CountryDto => Country
            CreateMap<CountryDto, Country>();
        }
    }
}