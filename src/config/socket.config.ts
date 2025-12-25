import { IoAdapter } from "@nestjs/platform-socket.io";
import { INestApplication } from "@nestjs/common";
import { ServerOptions } from "socket.io";

export class SocketConfig extends IoAdapter {
    constructor(private app: INestApplication){
        super(app);
    }

    createIOServer(port: number, options?: any) {
        const socketOptions: ServerOptions = {
            cors: {
                origin: "*",
                methods: ["GET", "POST"],
            },
            transports: ["websocket", "polling"],
            ...options
        };

        const server = super.createIOServer(port, socketOptions);

        return server
    }
}