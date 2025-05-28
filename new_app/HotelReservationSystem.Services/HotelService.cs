using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Interfaces;
using HotelReservationSystem.Core.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Services
{
    public class HotelService : IHotelService
    {
        private readonly IHotelRepository _hotelRepository;
        private readonly IMapper _mapper;
        
        public HotelService(IHotelRepository hotelRepository, IMapper mapper)
        {
            _hotelRepository = hotelRepository;
            _mapper = mapper;
        }
        
        public async Task<IEnumerable<HotelDto>> GetAllHotelsAsync()
        {
            var hotels = await _hotelRepository.GetHotelsWithCountriesAsync();
            return _mapper.Map<IEnumerable<HotelDto>>(hotels);
        }
        
        public async Task<HotelDto?> GetHotelByIdAsync(int id)
        {
            var hotel = await _hotelRepository.GetHotelWithCountryAsync(id);
            return hotel != null ? _mapper.Map<HotelDto>(hotel) : null;
        }
        
        public async Task<HotelDto> CreateHotelAsync(HotelDto hotelDto)
        {
            var hotel = _mapper.Map<Hotel>(hotelDto);
            await _hotelRepository.AddAsync(hotel);
            hotelDto.Id = hotel.Id;
            return hotelDto;
        }
        
        public async Task UpdateHotelAsync(int id, HotelDto hotelDto)
        {
            var hotel = await _hotelRepository.GetByIdAsync(id);
            if (hotel != null)
            {
                _mapper.Map(hotelDto, hotel);
                await _hotelRepository.UpdateAsync(hotel);
            }
        }
        
        public async Task DeleteHotelAsync(int id)
        {
            var hotel = await _hotelRepository.GetByIdAsync(id);
            if (hotel != null)
            {
                await _hotelRepository.DeleteAsync(hotel);
            }
        }
    }
}