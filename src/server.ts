import bcrypt from 'bcrypt';
import jwt, { JwtPayload, VerifyErrors } from 'jsonwebtoken';
import express, { Request, Response, Express, NextFunction } from 'express';
import { EStatuses, ITask, IUser } from './data';
import cors from 'cors';
import http from 'http';
import cookie from 'cookie';
import { ExtendedError, Server, Socket } from 'socket.io';

import cookieParser from 'cookie-parser';

export const SECRET_KEY = 'ASDK-12AD-KDASLS';
export let users: Array<IUser> = [];

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:5173',
    credentials: true,
  },
});

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
);

// Middleware to authenticate token in the socket connection
io.use((socket, next) => {
  const cookiesHeader = socket.handshake.headers.cookie || '';
  console.log(cookiesHeader);
  const token = cookiesHeader.split(';')
      .map((cookie) => cookie.trim())
      .find((cookie) => cookie.startsWith('token='))
      ?.replace('token=', '');

  if (!token) return next(new Error('Unauthorized'));

  jwt.verify(token, SECRET_KEY, (err: any, decoded: any) => {
    if (err) return next(new Error('Forbidden'));
    console.log(token);
    const user = users.find((u) => u.id === decoded.id);
    console.log(user);
    if (!user) return next(new Error('User not found'));
    socket.user = user;
    console.log(socket); // Attach user info to socket
    next();
  });
});

io.on('connection', (socket) => {
  const user = socket.user as IUser;
  console.log(user);
  if (!user) {
    return socket.disconnect(true);
  }
  // Событие для получения задач
  socket.on('getTasks', () => {
    console.log(user);
    const userTasks = user.tasks || [];
    socket.emit('tasksData', userTasks);
  });

  // Событие для добавления новой задачи
  socket.on('addTask', (task: Omit<ITask, 'id'>) => {
    const taskId = user.tasks.length
      ? user.tasks[user.tasks.length - 1].id + 1
      : 1;
    const newTask: ITask = { ...task, id: taskId };
    user.tasks.push(newTask);
    io.emit('taskAdded', newTask); // Рассылаем обновление всем клиентам
  });

  // Событие для обновления задачи
  socket.on('updateTask', (updatedTask: ITask) => {
    const taskIndex = user.tasks.findIndex(
      (task) => task.id === updatedTask.id,
    );
    if (taskIndex === -1) return;

    user.tasks[taskIndex] = { ...user.tasks[taskIndex], ...updatedTask };
    io.emit('taskUpdated', user.tasks[taskIndex]); // Рассылаем обновление всем клиентам
  });

  // Событие для удаления задачи
  socket.on('deleteTask', (taskId: number) => {
    const taskIndex = user.tasks.findIndex((task) => task.id === taskId);
    if (taskIndex === -1) return;

    const deletedTask = user.tasks.splice(taskIndex, 1)[0];
    io.emit('taskDeleted', deletedTask); // Рассылаем обновление всем клиентам
  });
});

app.post('/register', async (req, res) => {
  const { username, email, password, confirm_password } = req.body;
  if (password !== confirm_password) {
    res.status(400).json({ message: 'Passwords must match' });
    return;
  }

  if (users.find((user) => user.email === email)) {
    res.status(400).json({ message: 'User with this email already exists' });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newId = users.length
    ? Math.max(...users.map((user) => user.id)) + 1
    : 0;
  const newUser: IUser = {
    id: newId,
    username,
    email,
    password: hashedPassword,
    tasks: [],
  };
  users.push(newUser);
  res.status(201).json({ message: 'Registration successful' });
});

// Login event, setting JWT as an HTTP-only cookie
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    res.status(401).json({ message: 'Invalid credentials' });
    return;
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: '1h',
  });
  res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
  res
    .status(200)
    .json({ username: user.username, message: 'Login successful' });
});

app.get('/check-auth', (req: Request, res: Response) => {
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

    const user = users.find((u) => u.id === (decoded as JwtPayload).id);
    if (!user) {
      res.sendStatus(404);
      return;
    }

    res.status(200).json({ username: user.username });
  });
});

// Logout event
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

server.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
