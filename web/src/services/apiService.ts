import { env } from '../config/env';
import { HttpAdapter } from './api/httpAdapter';
import { mockAdapter } from './mock/mockAdapter';
import type { ApiAdapter } from './api/endpoints';
export const isMockMode = env.useMock;
export const api: ApiAdapter = env.useMock ? mockAdapter : new HttpAdapter(env.apiBaseUrl) as unknown as ApiAdapter;
