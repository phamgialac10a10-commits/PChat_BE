import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Message extends Document {
  @Prop({ required: true })
  roomId: number;

  @Prop({ required: true })
  senderId: number;

  @Prop()
  text: string;

  @Prop({ default: 'text' })
  type: string; // text | image | file | system

  @Prop({ type: Array, default: [] })
  attachments: any[];

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}

export const MessageSchema = SchemaFactory.createForClass(Message);