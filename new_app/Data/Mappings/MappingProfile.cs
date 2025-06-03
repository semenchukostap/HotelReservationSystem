using AutoMapper;
using new_app.DTOs;
using new_app.Models;
using new_app.ViewModels;

namespace new_app.Data.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Country, CountryDto>();
            
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName, opt => opt.MapFrom(src => src.Country.Name));
            
            // DTO to Domain
            CreateMap<CountryDto, Country>();
            CreateMap<HotelDto, Hotel>();
            
            // ViewModel to Domain and vice versa
            CreateMap<HotelViewModel, Hotel>();
            CreateMap<Hotel, HotelViewModel>();
        }
    }
}