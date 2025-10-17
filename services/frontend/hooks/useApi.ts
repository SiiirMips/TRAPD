import useSWR from 'swr';
import { fetcher } from '@/lib/fetcher';
export const useApi = (url: string, options?: any) => useSWR(url, fetcher, options);