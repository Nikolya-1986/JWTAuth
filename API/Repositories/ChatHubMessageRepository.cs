using API.Dtos;
using Microsoft.AspNetCore.SignalR;
using Repositories;

namespace API.Repositories
{
    public class ChatHubMessageRepository : Hub
    {
        private readonly ChatRepository _chatRepository;

        public ChatHubMessageRepository(ChatRepository chatRepository)
        {
            _chatRepository = chatRepository;
        }
        public async Task SendPrivateMessage(string userId, string message)
        {
             var chatMessage = new ChatMessage
            {
                SenderId = Context.UserIdentifier,
                ReceiverId = userId,
                Content = message,
                Timestamp = DateTime.UtcNow
            };

            await _chatRepository.AddMessage(chatMessage);
            await _chatRepository.SaveChangesAsync();
            
            await Clients.User(userId).SendAsync("ReceiveMessage", message);
        }

        public async Task SendGroupMessage(string groupName, string message)
        {
            await Clients.Group(groupName).SendAsync("ReceiveMessage", message);
        }

        public async Task SendBroadcastMessage(string message)
        {
            await Clients.All.SendAsync("ReceiveMessage", message);
        }

        public async Task JoinGroup(string groupName)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupName);
        }

        public async Task LeaveGroup(string groupName)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, groupName);
        }
    }
}