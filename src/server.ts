import express, { Request, Response, Express } from 'express';
import { EStatuses, ITask } from './data';
import { v4 } from 'uuid';

let tasks : Array<ITask> = [
  { id: 1, title: "Task 1", deadline: "2024-10-31", status: EStatuses.InProgress },
  { id: 2, title: "Task 2", deadline: "2024-11-01", status: EStatuses.Deadline },
  { id: 3, title: "Task 3", deadline: "2024-11-02", status: EStatuses.Complete },
  { id: 4, title: "Task 4", deadline: "2024-11-03", status: EStatuses.InProgress },
  { id: 5, title: "Task 5", deadline: "2024-11-04", status: EStatuses.Complete },
  { id: 6, title: "Task 6", deadline: "2024-11-05", status: EStatuses.InProgress },
  { id: 7, title: "Task 7", deadline: "2024-11-06", status: EStatuses.Deadline },
  { id: 8, title: "Task 8", deadline: "2024-11-07", status: EStatuses.Complete },
  { id: 9, title: "Task 9", deadline: "2024-11-08", status: EStatuses.InProgress },
  { id: 10, title: "Task 10", deadline: "2024-11-09", status: EStatuses.Complete },
];

const app: Express = express();

const port = 3000;
app.use(express.json());
app.use(function (req, res, next) {

  // Website you wish to allow to connect
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Request methods you wish to allow
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

  // Request headers you wish to allow
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');

  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Pass to next layer of middleware
  next();
});

app.get('/tasks', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.status(200).json(tasks);
});

app.post('/tasks', (req, res) => {
  const newTask: Omit<ITask, 'id'> = req.body;
  const task: ITask = {
    ...newTask,
    id: tasks.at(-1)?.id === undefined ? 0 : tasks.at(-1)!!.id + 1,
  };
  tasks.push(task);
  res.header('Access-Control-Allow-Origin', '*');
  res.status(201).json(task);
});

app.put('/tasks/:id', (req : Request, res : Response) : any => {
  const taskId = parseInt(req.params.id);
  const updatedTask: Partial<ITask> = req.body;
  const taskIndex = tasks.findIndex((task) => task.id === taskId);
  if (taskIndex === -1) {
    return res.status(404).json({ error: 'Task not found' });
  }
  tasks[taskIndex] = { ...tasks[taskIndex], ...updatedTask };
  res.header('Access-Control-Allow-Origin', '*');
  res.json(tasks[taskIndex]);
});

app.delete('/tasks/:id', (req: Request, res: Response) : any => {
  const taskId = parseInt(req.params.id);
  const taskIndex = tasks.findIndex(task => task.id === taskId);

  if (taskIndex === -1) {
      return res.status(404).json({ error: 'Task not found' });
  }

  const deletedTask = tasks.splice(taskIndex, 1)[0];
  res.header('Access-Control-Allow-Origin', '*');
  res.status(201).json(deletedTask);
});

// Start the server and listen on the specified port
app.listen(port, () => {
  // Log a message when the server is successfully running
  console.log(`Server is running on http://localhost:${port}`);
});

