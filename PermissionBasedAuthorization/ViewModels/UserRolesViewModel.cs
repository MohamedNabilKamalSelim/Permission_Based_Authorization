namespace PermissionBasedAuthorization.ViewModels
{
    public class UserRolesViewModel
    {
        public string userId { get; set; }
        public string userName { get; set; }
        public List<CheckBoxViewModel> Roles { get; set; }
    }
}
