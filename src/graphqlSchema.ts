import { buildSchema } from 'graphql';
import { ITask, IUser } from './data';

export const schema = buildSchema(`
  type Task {
    id: Int!
    title: String!
    deadline: String!
    status: String!
  }

  type User {
    id: Int!
    username: String!
    email: String!
    tasks: [Task]!
  }
  
  input TaskInput {
    id: Int!
    title: String!
    deadline: String!
    status: String!
  }

  input RegisterInput {
    username: String!
    email: String!
    password: String!
    confirmPassword: String!
  }

  input LoginInput {
    email: String!
    password: String!
  }

  type RegisterResponse {
    message: String!
  }

  type LoginResponse {
    username: String!
    message: String!
  }

  type LogoutResponse {
    message: String!
  }

  type CheckAuthResponse {
    username: String!
  }

  type Query {
    getUser: User
    getTasks: [Task]
    checkAuth: CheckAuthResponse!
  }

  type Mutation {
    register(input: RegisterInput): RegisterResponse
    login(input: LoginInput): LoginResponse
    logout: LogoutResponse
    addTask(task: TaskInput): Task
    updateTask(id: Int!, task: TaskInput): Task
    deleteTask(id: Int!): Task
  }
`);
  