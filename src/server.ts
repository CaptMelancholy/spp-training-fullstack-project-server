import bcrypt from 'bcrypt';
import jwt, { JwtPayload, VerifyErrors } from 'jsonwebtoken';
import express, { Request, Response, Express, NextFunction } from 'express';
import { EStatuses, ITask, IUser } from './data';
import cors from 'cors';
import http from 'http';
import { ExtendedError, Server, Socket } from 'socket.io';

import cookieParser from 'cookie-parser';

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
    }
  }
}

export const SECRET_KEY = 'ASDK-12AD-KDASLS';

export let users: Array<IUser> = [];

const app: Express = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:5173',
    credentials: true,
  },
});

const port = 3000;
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
);

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

const authenticateSocket = (
  socket: Socket,
  next: (err?: ExtendedError) => void
) => {
  const token = socket.handshake.auth.token;

  if (token) {
    jwt.verify(token, SECRET_KEY, (err: any, decoded: any) => {
      if (err || !decoded) return next(new Error('Authentication error'));

      const user = users.find((u) => u.id === (decoded as JwtPayload)?.id);
      if (!user) {
        return next(new Error('User not found'));
      }

      socket.data.user = user; // Сохраняем пользователя в socket.data
      next();
    });
  } else {
    next(new Error('No token provided'));
  }
};

const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const token = req.cookies?.token;
  if (!token) {
    res.sendStatus(401);
    return;
  }

  jwt.verify(token, SECRET_KEY, (err: any, decoded: any) => {
    if (err) {
      res.sendStatus(403);
      return;
    }

    const user = users.find((u) => u.id === decoded?.id);
    if (!user) {
      res.sendStatus(404);
      return;
    }

    req.user = user;
    next();
  });
};

// io.use(authenticateSocket);

io.on('connection', (socket: Socket) => {
  console.log('A user connected:', (socket as any).user);
  const user = socket.user as IUser;
  socket.on('getTasks', () => {
    socket.emit('tasksData', user.tasks);
  });

  socket.on('addTask', (taskData: Omit<ITask, 'id'>) => {
    const newTask: ITask = {
      ...taskData,
      id: user.tasks.length > 0 ? user.tasks[user.tasks.length - 1].id + 1 : 1,
    };
    user.tasks.push(newTask);
    io.to(socket.id).emit('taskAdded', newTask);
  });

  socket.on('updateTask', (updatedTask: Partial<ITask> & { id: number }) => {
    const taskIndex = user.tasks.findIndex(
      (task) => task.id === updatedTask.id,
    );
    if (taskIndex !== -1) {
      user.tasks[taskIndex] = { ...user.tasks[taskIndex], ...updatedTask };
      io.to(socket.id).emit('taskUpdated', user.tasks[taskIndex]);
    } else {
      socket.emit('error', { error: 'Task not found' });
    }
  });

  socket.on('deleteTask', (taskId: number) => {
    const taskIndex = user.tasks.findIndex((task) => task.id === taskId);
    if (taskIndex !== -1) {
      const [deletedTask] = user.tasks.splice(taskIndex, 1);
      io.to(socket.id).emit('taskDeleted', deletedTask);
    } else {
      socket.emit('error', { error: 'Task not found' });
    }
  });
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

app.post('/register', async (req: Request, res: Response) => {
  const { username, email, password, confirm_password } = req.body;
  if (password === confirm_password) {
    if (users.find((user) => user.email === email)) {
      res.status(400).json({ message: 'User with this login already exists' });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newId =
        users.length !== 0
          ? users.reduce(
              (maxId, item) => (item.id > maxId ? item.id : maxId),
              users[0].id,
            ) + 1
          : 0;
      const newUser: IUser = {
        id: newId,
        username,
        email,
        password: hashedPassword,
        tasks: [],
      };
      users.push(newUser);
      console.log(newUser);
      res.status(201).json({ message: 'Registration success' });
    }
  } else {
    res.status(400).json({ message: 'Passwords must be equal' });
  }
});
app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = users.find((user) => user.email === email);
  if (!user) {
    res.status(401).json({ message: 'Invalid credentials' });
  } else {
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ message: 'Invalid credentials' });
    } else {
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
        expiresIn: '1h',
      });

      res.cookie('token', token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000,
      });

      res
        .status(200)
        .json({ username: user.username, message: 'Login success' });
    }
  }
});

app.get('/check-auth', authenticateToken, (req: Request, res: Response) => {
  if (!req.user) {
    res.sendStatus(401);
    return;
  }

  res.status(200).json({ username: req.user.username });
});

app.post('/logout', (req: Request, res: Response) => {
  res.cookie('token', '', { httpOnly: true, secure: false, maxAge: 0 });
  res.json({ message: 'Logged out successfully' });
});

// Start the server and listen on the specified port
server.listen(port, () => {
  // Log a message when the server is successfully running
  console.log(`Server is running on http://localhost:${port}`);
});
