using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Core.ViewModels;

namespace HotelReservationSystem.Core.Mappings
{
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            // Hotel mappings
            CreateMap<Hotel, HotelDto>();
            CreateMap<HotelDto, Hotel>();
            CreateMap<Hotel, HotelViewModel>();
            
            // Country mappings
            CreateMap<Country, CountryDto>();
            
            // Customer mappings
            CreateMap<Customer, CustomerViewModel>();
            
            // Order mappings
            CreateMap<NewOrderDto, Order>();
            CreateMap<Order, OrderViewModel>();
        }
    }
}