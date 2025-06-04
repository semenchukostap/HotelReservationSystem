using AutoMapper;
using new_app.DTOs;
using new_app.Models;

namespace new_app;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Maps for Hotel
        CreateMap<Hotel, HotelDto>()
            .ForMember(dto => dto.CountryName, opt => opt.MapFrom(h => h.Country.Name));
            
        // Maps for Country
        CreateMap<Country, CountryDto>();
    }
}