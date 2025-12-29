import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message, MessageDocument } from './schemas/message.schema';

export interface CreateMessageDto {
  roomId: number;
  userId: number;
  content: string;
  aiStatus?: 'ok' | 'warning' | 'block';
  suggestion?: string | null;
}

@Injectable()
export class ChatService {
  constructor(
    @InjectModel(Message.name, 'mongoConnection')
    private messageModel: Model<MessageDocument>,
  ) {}

  async saveMessage(createMessageDto: CreateMessageDto): Promise<MessageDocument> {
    const message = new this.messageModel({
      ...createMessageDto,
      aiStatus: createMessageDto.aiStatus || 'ok',
    });
    return await message.save();
  }

  async getMessagesByRoomId(
    roomId: number,
    limit: number = 50,
  ): Promise<MessageDocument[]> {
    return await this.messageModel
      .find({ roomId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  async getMessagesByUserId(
    userId: number,
    limit: number = 50,
  ): Promise<MessageDocument[]> {
    return await this.messageModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  async deleteMessage(messageId: string): Promise<void> {
    await this.messageModel.findByIdAndDelete(messageId).exec();
  }

  async updateMessageStatus(
    messageId: string,
    aiStatus: string,
    suggestion?: string,
  ): Promise<MessageDocument | null> {
    return await this.messageModel
      .findByIdAndUpdate(
        messageId,
        {
          aiStatus,
          suggestion: suggestion || null,
        },
        { new: true },
      )
      .exec();
  }
}
