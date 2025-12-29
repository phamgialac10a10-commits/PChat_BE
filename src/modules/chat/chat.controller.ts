import { Controller, Get, Param, Delete, BadRequestException } from '@nestjs/common';
import { ChatService } from './chat.service';

@Controller('api/messages')
export class ChatController {
  constructor(private chatService: ChatService) {}

  @Get('room/:roomId')
  async getMessagesByRoom(@Param('roomId') roomId: string) {
    try {
      const id = parseInt(roomId, 10);
      if (isNaN(id)) {
        throw new BadRequestException('Invalid roomId');
      }
      return await this.chatService.getMessagesByRoomId(id);
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Get('user/:userId')
  async getMessagesByUser(@Param('userId') userId: string) {
    try {
      const id = parseInt(userId, 10);
      if (isNaN(id)) {
        throw new BadRequestException('Invalid userId');
      }
      return await this.chatService.getMessagesByUserId(id);
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  @Delete(':messageId')
  async deleteMessage(@Param('messageId') messageId: string) {
    try {
      await this.chatService.deleteMessage(messageId);
      return { success: true, message: 'Message deleted successfully' };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }
}

