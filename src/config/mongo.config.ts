import { MongooseModule } from '@nestjs/mongoose';
import mongoose from 'mongoose';

const mongoUri =
  process.env.MONGO_URI ||
  'mongodb+srv://laclac:lacpham2005@pchat.igp8a1c.mongodb.net/?retryWrites=true&w=majority&appName=PChat';

if (!mongoUri) {
  throw new Error('❌ Missing MONGO_URI in environment variables');
}



// ✅ Kết nối MongoDB
export const MongoConfig = MongooseModule.forRoot(mongoUri, {
  connectionName: 'mongoConnection', 
});
console.log('✅ MongoDB connected successfully!');

// mongoose.connection.on('connected', () => {
//   console.log('✅ MongoDB connected successfully!');
// });

// mongoose.connection.on('error', (err) => {
//   console.error('❌ MongoDB connection error:', err.message);
// });