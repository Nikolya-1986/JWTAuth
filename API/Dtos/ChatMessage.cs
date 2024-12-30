using Microsoft.EntityFrameworkCore;

namespace API.Dtos
{
    [Keyless]
    public class ChatMessage
    {
        public string? SenderId { get; set; }
        public string? ReceiverId { get; set; }
        public string? Content { get; set; }
        public DateTime Timestamp { get; set; }
    }
}