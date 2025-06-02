using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Controllers
{
    public class OrdersController : Controller
    {
        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult New()
        {
            return View();
        }

        [Authorize(Roles = RoleName.CanManageHotels)]
        public IActionResult Details(int id)
        {
            return View();
        }
    }
}