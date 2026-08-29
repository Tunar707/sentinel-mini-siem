import { z } from 'zod';

export const APP_NAME = "Sentinel Mini SIEM";
export type HealthStatus = { status: string; service: string; user?: any };

export type UserRole = "admin" | "analyst";

export interface UserContext {
  id: string;
  email: string;
  role: UserRole;
}

export interface AuthResponse {
  token: string;
  user: UserContext;
}

export const loginSchema = z.object({
  email: z.string().min(1, 'Email is required'),
  password: z.string().min(1, 'Password is required')
});
