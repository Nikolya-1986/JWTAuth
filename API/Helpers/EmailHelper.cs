using API.Models;
using RestSharp;

namespace Helpers
{
    public class EmailHelper
    {
        public RestResponse SendEmailPasswordReset(AppUser user, string resetLink)
        {
            var client = new RestClient("https://send.api.mailtrap.io/api/send");

            var request = new RestRequest
            {
                Method = Method.Post,
                RequestFormat = DataFormat.Json
            };
            
            request.AddHeader("Authorization", "Bearer 62a57db5c125073400f28db0b418c6d0");
            request.AddJsonBody(new
            {
                from = new { email = user.Email },
                to = new[] { new { email = user.Email } },
                template_uuid = user.Id,
                template_variables = new { user_email = user.Email, pass_reset_link = resetLink }
            });

            return client.Execute(request);
        }
    }
}