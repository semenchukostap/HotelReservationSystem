using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using HotelReservationSystem.Services;

namespace HotelReservationSystem.Controllers
{
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IHomeService _homeService;

        public HomeController(IHomeService homeService)
        {
            _homeService = homeService;
        }

        public ActionResult Index()
        {
            var viewModel = _homeService.GetIndexViewModel();
            return View(viewModel);
        }

        public ActionResult About()
        {
            var viewModel = _homeService.GetAboutViewModel();
            return View(viewModel);
        }
    }
}

namespace HotelReservationSystem.Services
{
    public interface IHomeService
    {
        IndexViewModel GetIndexViewModel();
        AboutViewModel GetAboutViewModel();
    }

    public class HomeService : IHomeService
    {
        public IndexViewModel GetIndexViewModel()
        {
            // Prepare the data for the Index view
            return new IndexViewModel();
        }

        public AboutViewModel GetAboutViewModel()
        {
            // Prepare the data for the About view
            return new AboutViewModel();
        }
    }

    public class IndexViewModel
    {
        // Properties and methods for the Index view model
    }

    public class AboutViewModel
    {
        // Properties and methods for the About view model
    }
}