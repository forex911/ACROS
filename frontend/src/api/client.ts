import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000',
  withCredentials: true,
});

let isRefreshing = false;
let failedQueue: Array<{ resolve: (value?: unknown) => void; reject: (reason?: any) => void }> = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token && config.headers && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

const isoDateRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;

const fixUtcDates = (obj: any): any => {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string' && isoDateRegex.test(obj)) {
    return obj + 'Z';
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      obj[i] = fixUtcDates(obj[i]);
    }
  } else if (typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      obj[key] = fixUtcDates(obj[key]);
    }
  }
  return obj;
};

api.interceptors.response.use(
  (response) => {
    response.data = fixUtcDates(response.data);
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    const isAuthEndpoint = originalRequest?.url?.includes('/auth/login') || 
                           originalRequest?.url?.includes('/auth/register') ||
                           originalRequest?.url?.includes('/auth/refresh');
    if (error.response?.status === 401 && !originalRequest._retry && !isAuthEndpoint) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const response = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        const { access_token } = response.data;
        localStorage.setItem('access_token', access_token);
        api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        originalRequest.headers['Authorization'] = `Bearer ${access_token}`;
        
        processQueue(null, access_token);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem('access_token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  }
);

export default api;
