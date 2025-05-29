using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HotelReservationSystem.Web.Controllers
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