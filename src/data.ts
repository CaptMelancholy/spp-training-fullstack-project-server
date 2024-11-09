export interface ITask {
    id: number;
    title: string;
    deadline: string;
    status: EStatuses;
}

export enum EStatuses {
    InProgress = "In Progress",
    Deadline = "Deadline",
    Complete = "Complete"
}

export interface IUser {
    id: number;
    username: string;
    email: string;
    password: string;
    tasks: Array<ITask>;
}