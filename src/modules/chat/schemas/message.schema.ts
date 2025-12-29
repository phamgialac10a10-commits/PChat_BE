import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type MessageDocument = Message & Document;

@Schema({ timestamps: true })
export class Message {
  @Prop({ required: true })
  roomId: number;

  @Prop({ required: true })
  userId: number;

  @Prop({ required: true })
  content: string;

  @Prop({
    enum: ['ok', 'warning', 'block'],
    default: 'ok',
  })
  aiStatus: string;

  @Prop({ default: null })
  suggestion: string | null;

  @Prop({ default: () => new Date() })
  createdAt: Date;
}

export const MessageSchema = SchemaFactory.createForClass(Message);
