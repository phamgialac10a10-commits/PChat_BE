import * as dotenv from 'dotenv';
dotenv.config();

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = new DocumentBuilder()
    .setTitle('PChat API Docs') // Tiêu đề
    .setDescription('Tài liệu API cho hệ thống PChat') // Mô tả
    .setVersion('1.0') // Phiên bản
    .addBearerAuth() // Nếu có JWT
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      explorer: true,
      filter: true,      
      showRequestDuration: true, // hiển thị thời gian request
      persistAuthorization: true, // giữ lại token giữa các lần refresh
      // docExpansion: 'none', 
    },
    customSiteTitle: 'PChat Swagger API Docs',
  });

  await app.listen(3000);
  console.log('🚀 Server running on http://localhost:3000');
  console.log('📘 Swagger docs: http://localhost:3000/api/docs');
}
bootstrap();
