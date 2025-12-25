export interface User {
  id?: number;
  fullname: string;
  email: string;
  password_hash: string;
  gender: string;
  is_active: boolean;
  access_token?: string;
  refresh_token?: string;
  access_expires_at?: Date;
  refresh_expires_at?: Date;
  role_id?: number;
  created_at?: Date;
}