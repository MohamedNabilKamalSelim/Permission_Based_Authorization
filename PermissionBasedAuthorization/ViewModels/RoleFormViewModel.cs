﻿using System.ComponentModel.DataAnnotations;

namespace PermissionBasedAuthorization.ViewModels
{
    public class RoleFormViewModel
    {
        [Required, StringLength(256)]
        public string Name { get; set; }
    }
}
