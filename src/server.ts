import bcrypt from 'bcrypt';
import jwt, { JwtPayload, VerifyErrors } from 'jsonwebtoken';
import express, { Request, Response, Express, NextFunction } from 'express';
import { EStatuses, ITask, IUser } from './data';
import cors from 'cors';

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

let tasks: Array<ITask> = [
  {
    id: 1,
    title: 'Task 1',
    deadline: '2024-10-31',
    status: EStatuses.InProgress,
  },
  {
    id: 2,
    title: 'Task 2',
    deadline: '2024-11-01',
    status: EStatuses.Deadline,
  },
  {
    id: 3,
    title: 'Task 3',
    deadline: '2024-11-02',
    status: EStatuses.Complete,
  },
  {
    id: 4,
    title: 'Task 4',
    deadline: '2024-11-03',
    status: EStatuses.InProgress,
  },
  {
    id: 5,
    title: 'Task 5',
    deadline: '2024-11-04',
    status: EStatuses.Complete,
  },
  {
    id: 6,
    title: 'Task 6',
    deadline: '2024-11-05',
    status: EStatuses.InProgress,
  },
  {
    id: 7,
    title: 'Task 7',
    deadline: '2024-11-06',
    status: EStatuses.Deadline,
  },
  {
    id: 8,
    title: 'Task 8',
    deadline: '2024-11-07',
    status: EStatuses.Complete,
  },
  {
    id: 9,
    title: 'Task 9',
    deadline: '2024-11-08',
    status: EStatuses.InProgress,
  },
  {
    id: 10,
    title: 'Task 10',
    deadline: '2024-11-09',
    status: EStatuses.Complete,
  },
];

const app: Express = express();

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

app.get('/tasks', authenticateToken, (req: Request, res: Response) => {
  const user = users.find((u) => u.id === req.user!.id);
  if (!user) res.status(404).json({ error: 'User not found' });
  else {
    res.status(200).json(user.tasks);
  }
});

app.post('/tasks', authenticateToken, (req: Request, res: Response) => {
  const user = users.find((u) => u.id === req.user!.id);
  if (!user) res.status(404).json({ error: 'User not found' });
  else {
    const newTask: Omit<ITask, 'id'> = req.body;
    const task: ITask = {
      ...newTask,
      id: user.tasks.at(-1)?.id === undefined ? 0 : user.tasks.at(-1)!.id + 1,
    };
    user.tasks.push(task);
    res.status(201).json(task);
  }
});

app.put('/tasks/:id', authenticateToken, (req: Request, res: Response) => {
  const user = users.find((u) => u.id === req.user!.id);
  if (!user) res.status(404).json({ error: 'User not found' });
  else {
    const taskId = parseInt(req.params.id);
    const updatedTask: Partial<ITask> = req.body;
    const taskIndex = user.tasks.findIndex((task) => task.id === taskId);

    if (taskIndex === -1) {
      res.status(404).json({ error: 'Task not found' });
    } else {
      user.tasks[taskIndex] = { ...user.tasks[taskIndex], ...updatedTask };
      res.json(user.tasks[taskIndex]);
    }
  }
});

app.delete('/tasks/:id', authenticateToken, (req: Request, res: Response) => {
  const user = users.find((u) => u.id === req.user!.id);
  if (!user) res.status(404).json({ error: 'User not found' });
  else {
    const taskId = parseInt(req.params.id);
    const taskIndex = user.tasks.findIndex((task) => task.id === taskId);

    if (taskIndex === -1) {
      res.status(404).json({ error: 'Task not found' });
    } else {
      const deletedTask = user.tasks.splice(taskIndex, 1)[0];
      res.status(201).json(deletedTask);
    }
  }
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
app.listen(port, () => {
  // Log a message when the server is successfully running
  console.log(`Server is running on http://localhost:${port}`);
});
