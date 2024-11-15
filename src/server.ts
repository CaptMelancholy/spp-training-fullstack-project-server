import bcrypt from 'bcrypt';
import jwt, { JwtPayload, VerifyErrors } from 'jsonwebtoken';
import express, { Request, Response, Express, NextFunction } from 'express';
import { EStatuses, ITask, IUser } from './data';
import cors from 'cors';
import http from 'http';
import cookie from 'cookie';
import { ExtendedError, Server, Socket } from 'socket.io';

import cookieParser from 'cookie-parser';
import { graphqlHTTP } from 'express-graphql';
import { schema } from './graphqlSchema';

export const SECRET_KEY = 'ASDK-12AD-KDASLS';
export let users: Array<IUser> = [];

declare module 'express' {
  export interface Request {
    user?: IUser;
  }
}

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }),
);

export const rootValue = {
  getUser: (args: any, context: { user: IUser }) => {
    return context.user;
  },
  getTasks: (args: any, context: { user: IUser }) => {
    return context.user.tasks;
  },
  addTask: (args: { task: Omit<ITask, 'id'> }, context: { user: IUser }) => {
    const user = context.user;
    const taskId = user.tasks.length
      ? user.tasks[user.tasks.length - 1].id + 1
      : 1;
    const newTask: ITask = { ...args.task, id: taskId };
    user.tasks.push(newTask);
    return newTask;
  },
  updateTask: (
    args: { id: number; task: Partial<ITask> },
    context: { user: IUser },
  ) => {
    const user = context.user;
    const taskIndex = user.tasks.findIndex((task) => task.id === args.id);
    if (taskIndex === -1) throw new Error('Task not found');

    user.tasks[taskIndex] = { ...user.tasks[taskIndex], ...args.task };
    return user.tasks[taskIndex];
  },
  deleteTask: (args: { id: number }, context: { user: IUser }) => {
    const user = context.user;
    const taskIndex = user.tasks.findIndex((task) => task.id === args.id);
    if (taskIndex === -1) throw new Error('Task not found');

    const [deletedTask] = user.tasks.splice(taskIndex, 1);
    return deletedTask;
  },
  checkAuth: (args: any, context: { token?: string }) => {
    if (!context.token) throw new Error('Unauthorized');

    const decoded = jwt.verify(context.token, SECRET_KEY) as { id: number };
    const user = users.find((u) => u.id === decoded.id);
    if (!user) throw new Error('User not found');

    return { username: user.username };
  },
  register: async (args: {
    input: {
      username: string;
      email: string;
      password: string;
      confirmPassword: string;
    };
  }) => {
    const { username, email, password, confirmPassword } = args.input;

    if (password !== confirmPassword) throw new Error('Passwords must match');
    if (users.find((user) => user.email === email))
      throw new Error('User with this email already exists');

    const hashedPassword = await bcrypt.hash(password, 10);
    const newId = users.length
      ? Math.max(...users.map((user) => user.id)) + 1
      : 1;
    const newUser: IUser = {
      id: newId,
      username,
      email,
      password: hashedPassword,
      tasks: [],
    };
    users.push(newUser);

    return { message: 'Registration successful' };
  },
  login: async (
    args: { input: { email: string; password: string } },
    context: { res: Response },
  ) => {
    const { email, password } = args.input;

    const user = users.find((u) => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password)))
      throw new Error('Invalid credentials');

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: '1h',
    });
    context.res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });

    return { username: user.username, message: 'Login successful' };
  },
  logout: (args: any, context: { res: any }) => {
    context.res.clearCookie('token');
    return { message: 'Logged out successfully' };
  },
};
const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const query = req.body.query;
  console.log(req.body);
  console.log(query);
  // Проверяем, если запрос содержит мутацию "registration" или "login"
  if (query && (query.includes('register') || query.includes('login')) || query.includes('checkAuth')) {
    // Если это нужные мутации, пропускаем дальше
    return next();
  }
  const token = req.cookies?.token;
  console.log(req);
  if (!token) {
    // Вместо res.sendStatus выбрасываем ошибку
    throw new Error("Unauthorized: No token provided");
  }

  jwt.verify(token, SECRET_KEY, (err: any, decoded: any) => {
    if (err) {
      throw new Error("Forbidden: Invalid token");
    }

    const user = users.find((u) => u.id === decoded.id);
    if (!user) {
      throw new Error("Not Found: User does not exist");
    }

    req.user = user;
    next();
  });
};


app.use(
  '/graphql',
  (req, res, next) => {
    try {
      authMiddleware(req, res, next); // Проверка токена
    } catch (error) {
      next(error); // Передача ошибки в обработчик
    }
  },
  graphqlHTTP((req: any, res: any) => ({
    schema,
    rootValue: rootValue,
    graphiql: true,
    context: {
      req,
      res,
      token: req.cookies?.token, // Передача токена из куки
      user: req.user,
    },
    // context: { user: req.user },
  })),
);

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
