export const env = {
 apiBaseUrl: (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api',
 useMock: String(import.meta.env.VITE_USE_MOCK ?? 'true').toLowerCase() !== 'false',
};
