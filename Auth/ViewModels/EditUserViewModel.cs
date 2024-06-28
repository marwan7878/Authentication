using Auth.Models;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Auth.ViewModels
{
    public class EditUserViewModel
    {
        public string Id { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 3)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 3)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        //[Remote("CheckEmail" ,"Users", AdditionalFields ="email" , ErrorMessage = "Email is already exists!")]
        public string Email { get; set; }
        
        [Required]
        [Display(Name = "User Name")]
        public string Username { get; set; }

        
        [Display(Name = "Roles")]
        [CheckBoxRequired]
        public List<RoleViewModel> Roles { get; set; }

    }
}
