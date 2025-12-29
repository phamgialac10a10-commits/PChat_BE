import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { SocketConfig } from './config/socket.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Setup WebSocket adapter
  app.useWebSocketAdapter(new SocketConfig(app));

  const config = new DocumentBuilder()
    .setTitle('PChat API Docs')
    .setDescription('Tài liệu API cho hệ thống PChat')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      explorer: true,
      filter: true,
      showRequestDuration: true,
      persistAuthorization: true,
    },
    customSiteTitle: 'PChat Swagger API Docs',
  });

  await app.listen(3000);
  console.log('🚀 Server running on http://localhost:3000');
  console.log('📘 Swagger docs: http://localhost:3000/api/docs');
  console.log('💬 WebSocket ready at ws://localhost:3000/chat');
}
bootstrap();

