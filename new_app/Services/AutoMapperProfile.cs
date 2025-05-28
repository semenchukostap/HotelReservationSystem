using AutoMapper;
using new_app.DTOs;
using new_app.Models;

namespace new_app.Services
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // Replace the legacy Mapper.CreateMap with modern AutoMapper CreateMap method
            CreateMap<Hotel, HotelDto>();
            CreateMap<HotelDto, Hotel>();
            
            CreateMap<Country, CountryDto>();
        }
    }
}