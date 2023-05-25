import { Request } from 'express';

export const extractAgentIpFromRequest = (
  request: Request
): { agent: string; ip: string } => {
  let ip =
    request.headers['x-forwarded-for'] || request.socket.remoteAddress || null;
  if (Array.isArray(ip)) {
    ip = ip.join(';');
  }
  const agent = request.headers['user-agent'];
  return { agent, ip };
};
