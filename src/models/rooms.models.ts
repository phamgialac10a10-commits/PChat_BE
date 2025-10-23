export interface Room {
  id?: number;
  name: string;
  type: 'private' | 'group';
  created_at?: Date;
}
