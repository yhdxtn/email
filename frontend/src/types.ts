/** API tables are heterogeneous; mutations use their own validated field definitions. */
export type Row = Record<string, any>;
export type Field = { key: string; label: string; type?: 'text'|'password'|'email'|'number'|'textarea'|'select'|'checkbox'; required?: boolean; hint?: string; min?: number; max?: number; options?: {value:string;label:string}[]; value?: string|number|boolean };
export type Section = 'overview'|'nodes'|'domains'|'mailboxes'|'aliases'|'sending'|'queue'|'health'|'backups'|'tasks'|'audit'|'admins'|'settings'|'website'|'sessions';
