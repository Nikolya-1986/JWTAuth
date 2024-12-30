using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using API.Repositories;

namespace API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class ChatHubController : ControllerBase
    {
        private readonly ChatHubMessageRepository _chatHubMessageRepository;

        public ChatHubController(ChatHubMessageRepository chatHubMessageRepository)
        {
            _chatHubMessageRepository = chatHubMessageRepository;
        }

        // api/chatHub/sendPrivateMessage
        [AllowAnonymous]
        [HttpPost("sendPrivateMessage")]
        public async Task SendPrivateMessage(string userId, string message)
        {
            await _chatHubMessageRepository.SendPrivateMessage(userId, message);
        }

        // api/chatHub/SendGroupMessage
        [AllowAnonymous]
        [HttpPost("SendGroupMessage")]
        public async Task SendGroupMessage(string groupName, string message)
        {
            await _chatHubMessageRepository.SendGroupMessage(groupName, message);
        }

        // api/chatHub/SendBroadcastMessage
        [AllowAnonymous]
        [HttpPost("SendBroadcastMessage")]
        public async Task SendBroadcastMessage(string message)
        {
            await _chatHubMessageRepository.SendBroadcastMessage(message);
        }

        // api/chatHub/JoinGroup
        [AllowAnonymous]
        [HttpPost("JoinGroup")]
        public async Task JoinGroup(string groupName)
        {
            await _chatHubMessageRepository.JoinGroup(groupName);
        }

        // api/chatHub/LeaveGroup
        [AllowAnonymous]
        [HttpPost("LeaveGroup")]
        public async Task LeaveGroup(string groupName)
        {
            await _chatHubMessageRepository.LeaveGroup(groupName);
        }
    }
}