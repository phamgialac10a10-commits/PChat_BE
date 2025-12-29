import {
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { ChatService } from './chat.service';

@WebSocketGateway({
  namespace: 'chat',
  cors: {
    origin: '*',
  },
})
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  constructor(private chatService: ChatService) {}

  handleConnection(client: Socket) {
    console.log(`[Socket] Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    console.log(`[Socket] Client disconnected: ${client.id}`);
  }

  @SubscribeMessage('join_room')
  handleJoinRoom(
    client: Socket,
    payload: { roomId: number; userId: number },
  ) {
    const roomKey = `room_${payload.roomId}`;
    client.join(roomKey);

    this.server.to(roomKey).emit('user_joined', {
      userId: payload.userId,
      roomId: payload.roomId,
      message: `User ${payload.userId} joined`,
    });

    console.log(
      `[Chat] User ${payload.userId} joined room ${payload.roomId}`,
    );
  }

  @SubscribeMessage('leave_room')
  handleLeaveRoom(
    client: Socket,
    payload: { roomId: number; userId: number },
  ) {
    const roomKey = `room_${payload.roomId}`;
    client.leave(roomKey);

    this.server.to(roomKey).emit('user_left', {
      userId: payload.userId,
      roomId: payload.roomId,
      message: `User ${payload.userId} left`,
    });

    console.log(`[Chat] User ${payload.userId} left room ${payload.roomId}`);
  }

  @SubscribeMessage('send_message')
  async handleSendMessage(
    client: Socket,
    payload: {
      roomId: number;
      userId: number;
      content: string;
      aiStatus?: 'ok' | 'warning' | 'block';
      suggestion?: string;
    },
  ) {
    try {
      const savedMessage = await this.chatService.saveMessage({
        roomId: payload.roomId,
        userId: payload.userId,
        content: payload.content,
        aiStatus: payload.aiStatus || 'ok',
        suggestion: payload.suggestion || null,
      });

      const roomKey = `room_${payload.roomId}`;
      this.server.to(roomKey).emit('new_message', {
        _id: savedMessage._id,
        roomId: savedMessage.roomId,
        userId: savedMessage.userId,
        content: savedMessage.content,
        aiStatus: savedMessage.aiStatus,
        suggestion: savedMessage.suggestion,
        createdAt: savedMessage.createdAt,
      });

      console.log(
        `[Chat] Message saved - Room: ${payload.roomId}, User: ${payload.userId}`,
      );
    } catch (error) {
      client.emit('error', {
        message: 'Failed to save message',
        error: error.message,
      });

      console.error(`[Chat] Error saving message:`, error.message);
    }
  }

  @SubscribeMessage('typing')
  handleTyping(
    client: Socket,
    payload: { roomId: number; userId: number; isTyping: boolean },
  ) {
    const roomKey = `room_${payload.roomId}`;
    this.server.to(roomKey).emit('user_typing', {
      userId: payload.userId,
      isTyping: payload.isTyping,
    });
  }
}
