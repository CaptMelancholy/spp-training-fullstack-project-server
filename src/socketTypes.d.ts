import { IUser } from './data'; // Импортируйте IUser из вашего файла типов

declare module 'socket.io' {
  interface Socket {
    user?: IUser;
  }
}
