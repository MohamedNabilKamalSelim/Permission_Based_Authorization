namespace PermissionBasedAuthorization.ViewModels
{
    public class PermissionsFormViewModel
    {
        public string roleId { get; set; }
        public string roleName { get; set; }
        public List<CheckBoxViewModel> roleClaims { get; set; }
    }
}
