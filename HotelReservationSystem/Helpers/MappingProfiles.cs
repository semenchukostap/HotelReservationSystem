using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using System;

namespace HotelReservationSystem.Helpers
{
    /// <summary>
    /// Defines AutoMapper profiles for mapping between entities and DTOs
    /// </summary>
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            // Hotel mappings
            CreateMap<Hotel, HotelDto>();
            CreateMap<HotelDto, Hotel>();

            // Country mappings
            CreateMap<Country, CountryDto>();
            CreateMap<CountryDto, Country>();

            // Customer mappings
            CreateMap<Customer, CustomerDto>();
            CreateMap<CustomerDto, Customer>();

            // Order mappings
            CreateMap<Order, OrderDto>();
            CreateMap<OrderDto, Order>();

            // Special mapping for new order creation
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.Id, opt => opt.Ignore())
                .ForMember(o => o.Customer, opt => opt.Ignore())
                .ForMember(o => o.Hotel, opt => opt.Ignore())
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(o => o.NumberOfDays, opt => opt.MapFrom(src => 
                    (src.EndDate - src.StartDate).Days))
                .ForMember(o => o.FullPrice, opt => opt.Ignore()); // Will be calculated in the service

            // ApplicationUser mappings
            CreateMap<ApplicationUser, ApplicationUserDto>()
                .ForMember(dest => dest.Password, opt => opt.Ignore()) // Don't map password for security reasons
                .ForMember(dest => dest.PasswordConfirmation, opt => opt.Ignore());
                
            CreateMap<ApplicationUserDto, ApplicationUser>()
                .ForMember(dest => dest.PasswordHash, opt => opt.Ignore())
                .ForMember(dest => dest.SecurityStamp, opt => opt.Ignore());
        }
    }
}