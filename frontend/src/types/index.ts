export interface User {
  username: string;
  email: string;
  roles: string[];
  supabaseUserId?: string;
}

export interface Job {
  job_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  file_hash: string;
  created_at: string;
}

export interface AnalysisReport {
  report_id: string;
  job_id: string;
  risk_score: number;
  is_malicious: boolean;
  summary: string;
  iocs: {
    ips: string[];
    domains: string[];
    hashes: string[];
  };
}
