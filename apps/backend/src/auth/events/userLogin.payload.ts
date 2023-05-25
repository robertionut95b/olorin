export class UserLoginEvent {
  private _userId: string;

  private _agent: string;

  private _ip: string;

  constructor(userId: string, agent: string, ip: string) {
    this._userId = userId;
    this._agent = agent;
    this._ip = ip;
  }

  public get userId(): string {
    return this._userId;
  }

  public get agent(): string {
    return this._agent;
  }

  public get ip(): string {
    return this._ip;
  }
}
