using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO mappings
            CreateMap<Hotel, HotelDto>()
                .ForMember(dto => dto.CountryName, opt => opt.MapFrom(h => h.Country != null ? h.Country.Name : string.Empty));

            CreateMap<Country, CountryDto>();

            // DTO to Domain mappings
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
            CreateMap<NewOrderDto, Order>();
            
            // Add any additional mappings here
        }
    }
}